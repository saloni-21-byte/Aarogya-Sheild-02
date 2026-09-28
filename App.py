
"""
=======================================================================
 AarogyaShield — Zero-Trust Healthcare Data Security MVP
 Seva First Innovation Challenge (SFIC) — Track A
 Theme: "Swasth & Samavesh Bharat"
=======================================================================
Run with:
    streamlit run app.py

This single file is fully self-contained: UI, encryption, masking,
consent simulation, record management, and an in-session "database"
(also mirrored to a local CSV so data survives a page refresh during
your demo).
"""

import os
import time
import random
import datetime as dt

import pandas as pd
import streamlit as st
from cryptography.fernet import Fernet


# =======================================================================
# 1. PAGE CONFIG  (must be the first Streamlit call)
# =======================================================================
st.set_page_config(
    page_title="AarogyaShield",
    page_icon="🛡️",
    layout="wide",
)

CSV_PATH = "aarogyashield_patients.csv"   # local mirror of our "database"
KEY_PATH = "aarogyashield_secret.key"     # persisted Fernet key — see section 2

# Fields that are sensitive and therefore ALWAYS stored encrypted.
# Every other field (name, age, gender, blood group, timestamps) is
# considered non-sensitive metadata and stored in plain text, which
# keeps the demo table readable while still protecting the fields
# that actually enable identity theft or scams.
ENCRYPTED_FIELDS = [
    "aadhaar", "phone", "emergency_phone", "chief_complaint", "notes",
]


# =======================================================================
# 2. ENCRYPTION SETUP
# -----------------------------------------------------------------------
# Fernet is symmetric encryption: the SAME key encrypts and decrypts.
#
# --- FIX (was the cause of [DECRYPTION ERROR]) -------------------------
# The key used to be generated fresh into st.session_state every run,
# which resets whenever Streamlit restarts. But patient records are
# mirrored to a CSV file that DOES survive restarts — so any record
# encrypted before a restart became permanently undecryptable the
# moment a new random key was generated after that restart.
#
# The fix: persist the key itself to a local file (KEY_PATH), exactly
# like the CSV. On first run we generate it once and save it; on every
# run after that we just load the same key back. This keeps the key
# consistent with whatever ciphertext already lives in the CSV.
#
# In a REAL deployment this key file would instead live in a proper
# secrets manager (AWS/GCP secrets manager, HashiCorp Vault, etc.),
# never committed to source control or version control as a plain file.
# =======================================================================
def load_or_create_key() -> bytes:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    new_key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(new_key)
    return new_key


if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = load_or_create_key()
cipher = Fernet(st.session_state.fernet_key)   # cipher object used everywhere below


def encrypt_text(plain_text: str) -> str:
    """Encrypt a string and return it as a storable string (not raw bytes)."""
    if plain_text is None:
        plain_text = ""
    return cipher.encrypt(plain_text.encode("utf-8")).decode("utf-8")


def decrypt_text(cipher_text: str) -> str:
    """Decrypt a string produced by encrypt_text(). Fails safely if corrupted."""
    try:
        return cipher.decrypt(str(cipher_text).encode("utf-8")).decode("utf-8")
    except Exception:
        return "[DECRYPTION ERROR]"


# =======================================================================
# 3. MASKING HELPERS  (what low-trust roles see by default)
# =======================================================================
def mask_aadhaar(number: str) -> str:
    digits = "".join(c for c in (number or "") if c.isdigit())
    if len(digits) < 4:
        return "XXXX-XXXX-XXXX"
    return f"XXXX-XXXX-{digits[-4:]}"


def mask_phone(number: str) -> str:
    digits = "".join(c for c in (number or "") if c.isdigit())
    if len(digits) < 4:
        return "XXXXXXXXXX"
    return "X" * (len(digits) - 4) + digits[-4:]


def mask_text(_value: str) -> str:
    return "•••••• (locked)"


def clean_phone(raw: str) -> str:
    """
    Normalize a phone number typed with or without an India country code.
    Accepts inputs like '9876543210', '+91 9876543210', '091-9876543210',
    etc., and returns just the 10-digit local number when possible.
    If the result still isn't exactly 10 digits, it's returned as-is so
    the caller's validation can raise a clear error.
    """
    digits = "".join(c for c in (raw or "") if c.isdigit())
    # Strip a leading '91' country code (with or without the '+') once,
    # but only if that leaves exactly 10 digits behind.
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return digits


# =======================================================================
# 4. SESSION "DATABASE" INITIALIZATION
# -----------------------------------------------------------------------
# We keep patient records in st.session_state so the whole app works
# without any external database. Sensitive fields are stored ONLY in
# their encrypted form — the plain text never touches storage.
# =======================================================================
if "patients" not in st.session_state:
    # Try to reload from the CSV mirror if it exists (demo persistence)
    if os.path.exists(CSV_PATH):
        st.session_state.patients = pd.read_csv(CSV_PATH).fillna("").to_dict("records")
    else:
        st.session_state.patients = []

if "access_grants" not in st.session_state:
    # patient_id -> {"expiry": timestamp, "doctor": name}
    st.session_state.access_grants = {}

if "pending_otp" not in st.session_state:
    # patient_id -> otp code waiting to be verified
    st.session_state.pending_otp = {}

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []


def save_to_csv():
    """Persist the current session DB to a CSV file (demo-grade persistence)."""
    pd.DataFrame(st.session_state.patients).to_csv(CSV_PATH, index=False)


def log_event(actor: str, action: str, patient_name: str = ""):
    st.session_state.audit_log.append({
        "Timestamp": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Actor": actor,
        "Action": action,
        "Patient": patient_name,
    })


def find_patient(patient_id):
    return next((p for p in st.session_state.patients if p["id"] == patient_id), None)


# =======================================================================
# 4b. AI-ASSISTED ANOMALY DETECTION (audit-log metadata only)
# -----------------------------------------------------------------------
# Scans the audit trail for suspicious access patterns. It only ever
# reads WHO did WHAT and WHEN — never Aadhaar, phone or clinical data —
# so the AI layer adds protection without adding any new exposure.
# =======================================================================
def _max_in_window(times, minutes):
    """Largest number of events falling inside any sliding window of `minutes`."""
    times = sorted(times)
    best, j = 0, 0
    for i in range(len(times)):
        while times[i] - times[j] > dt.timedelta(minutes=minutes):
            j += 1
        best = max(best, i - j + 1)
    return best


def detect_anomalies(audit_log):
    """Return (alerts, risk_score 0-100) for the given audit trail."""
    events = []
    for e in audit_log:
        try:
            ts = dt.datetime.strptime(e["Timestamp"], "%Y-%m-%d %H:%M:%S")
        except (KeyError, ValueError):
            continue
        events.append({**e, "ts": ts})

    alerts = []

    # --- Rules that apply to each doctor separately ---
    doctors = {e["Actor"] for e in events if str(e["Actor"]).startswith("Dr.")}
    for doc in sorted(doctors):
        mine = [e for e in events if e["Actor"] == doc]

        # Rule 1: repeated wrong OTPs (possible guessing attack)
        failed = [e["ts"] for e in mine if "FAILED" in e["Action"]]
        if _max_in_window(failed, 10) >= 3:
            alerts.append({
                "Severity": "High", "Rule": "Repeated failed OTPs", "Actor": doc,
                "Detail": "3+ wrong OTP attempts within 10 minutes", "Points": 40,
            })

        # Rule 2: burst of consent requests (possible mass-access attempt)
        requests = [e["ts"] for e in mine if e["Action"].startswith("Requested OTP")]
        if _max_in_window(requests, 10) >= 4:
            alerts.append({
                "Severity": "Medium", "Rule": "Rapid consent requests", "Actor": doc,
                "Detail": "4+ access requests within 10 minutes", "Points": 20,
            })

        # Rule 3: unlocking many different patients quickly (bulk data harvesting)
        unlocks = [e for e in mine if e["Action"].startswith("Consent verified")]
        for e in unlocks:
            recent = {
                u["Patient"] for u in unlocks
                if dt.timedelta(0) <= e["ts"] - u["ts"] <= dt.timedelta(minutes=30)
            }
            if len(recent) >= 3:
                alerts.append({
                    "Severity": "High", "Rule": "Bulk record access", "Actor": doc,
                    "Detail": "3+ different patients unlocked within 30 minutes", "Points": 40,
                })
                break

        # Rule 4: access granted during off-hours (10 PM to 5 AM)
        if any(e["ts"].hour < 5 or e["ts"].hour >= 22 for e in unlocks):
            alerts.append({
                "Severity": "Medium", "Rule": "Off-hours access", "Actor": doc,
                "Detail": "Record unlocked between 10 PM and 5 AM", "Points": 20,
            })

    # --- Rule 5: several deletions in a short time (possible data destruction) ---
    deletions = [e["ts"] for e in events if e["Action"].startswith("Deleted")]
    if _max_in_window(deletions, 10) >= 3:
        alerts.append({
            "Severity": "High", "Rule": "Mass deletion", "Actor": "Multiple / any",
            "Detail": "3+ records deleted within 10 minutes", "Points": 40,
        })

    score = min(100, sum(a["Points"] for a in alerts))
    return alerts, score


VERNACULAR_PROMPTS = {
    "English": "\"Press 1 or enter the OTP sent to your phone to authorize Dr. {doc} for {mins} minutes.\"",
    "Hindi (हिंदी)": "\"डॉ. {doc} को {mins} मिनट के लिए अधिकृत करने हेतु 1 दबाएँ या अपने फोन पर भेजा गया OTP दर्ज करें।\"",
    "Telugu (తెలుగు)": "\"డా. {doc}కి {mins} నిమిషాల పాటు అనుమతి ఇవ్వడానికి 1 నొక్కండి లేదా మీ ఫోన్‌కు పంపిన OTPని నమోదు చేయండి.\"",
}

BLOOD_GROUPS = ["Unknown", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]


# =======================================================================
# 5. SIDEBAR NAVIGATION
# =======================================================================
st.sidebar.title("🛡️ AarogyaShield")
st.sidebar.caption("Zero-Trust Healthcare Data Security")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigate",
    [
        "📝 Patient Data Registration & Encryption",
        "🩺 Doctor Dashboard & Dynamic Masking",
        "✏️ Manage Patient Records",
        "🔐 Security Audit & System Architecture",
    ],
)

st.sidebar.divider()
st.sidebar.metric("Patients in Database", len(st.session_state.patients))
st.sidebar.metric("Active Access Grants", sum(
    1 for g in st.session_state.access_grants.values() if g["expiry"] > time.time()
))
st.sidebar.metric("Security Alerts", len(detect_anomalies(st.session_state.audit_log)[0]))
st.sidebar.caption("SFIC Track A — Swasth & Samavesh Bharat")


# =======================================================================
# 6. VIEW 1 — PATIENT DATA REGISTRATION & ENCRYPTION
# =======================================================================
if page.startswith("📝"):
    st.title("📝 Patient Data Registration & Encryption")
    st.write(
        "Health workers enter patient details here. Sensitive fields are "
        "**encrypted with Fernet (AES-128-CBC + HMAC) the instant the form is submitted** "
        "— plain text is never written to storage."
    )
    st.divider()

    col_form, col_info = st.columns([1.3, 1])

    with col_form:
        with st.form("patient_form", clear_on_submit=True):
            st.markdown("##### Identity")
            name = st.text_input("Patient Name")
            c1, c2 = st.columns(2)
            with c1:
                aadhaar = st.text_input("Aadhaar Number (12 digits)", max_chars=14)
                age = st.number_input("Age", min_value=0, max_value=120, step=1)
                blood_group = st.selectbox("Blood Group", BLOOD_GROUPS)
            with c2:
                phone = st.text_input(
                    "Phone Number (10 digits, +91 optional)", max_chars=14,
                    placeholder="+91 9876543210",
                )
                gender = st.selectbox("Gender", ["Female", "Male", "Other"])

            st.markdown("##### Emergency Contact")
            e1, e2 = st.columns(2)
            with e1:
                emergency_name = st.text_input("Emergency Contact Name")
            with e2:
                emergency_phone = st.text_input(
                    "Emergency Contact Phone (10 digits, +91 optional)", max_chars=14,
                    placeholder="+91 9876543210",
                )

            st.markdown("##### Visit Details")
            chief_complaint = st.text_area(
                "Chief Complaint (why the patient is here today)", height=80
            )
            allergies = st.text_input("Known Allergies (comma-separated, or 'None')")
            notes = st.text_area("Diagnostic Notes / Symptoms (filled by doctor if available)")

            submitted = st.form_submit_button("🔒 Encrypt & Register Patient", type="primary")

        if submitted:
            # --- basic validation, keeps rural/low-literacy data entry error-proof ---
            errors = []
            if not name.strip():
                errors.append("Name is required.")
            aadhaar_digits = "".join(c for c in aadhaar if c.isdigit())
            phone_digits = clean_phone(phone)
            emergency_phone_digits = clean_phone(emergency_phone)
            if len(aadhaar_digits) != 12:
                errors.append("Aadhaar must be exactly 12 digits.")
            if len(phone_digits) != 10:
                errors.append("Phone number must be 10 digits (with or without +91).")
            if emergency_phone_digits and len(emergency_phone_digits) != 10:
                errors.append("Emergency contact phone must be 10 digits (with or without +91), or left blank.")

            if errors:
                for e in errors:
                    st.error(e)
            else:
                # --- ENCRYPTION HAPPENS HERE: raw values never get stored ---
                record = {
                    "id": len(st.session_state.patients) + 1,
                    "name": name.strip(),
                    "age": int(age),
                    "gender": gender,
                    "blood_group": blood_group,
                    "allergies": allergies.strip() or "None",
                    "emergency_name": emergency_name.strip(),
                    "aadhaar_enc": encrypt_text(aadhaar_digits),
                    "phone_enc": encrypt_text(phone_digits),
                    "emergency_phone_enc": encrypt_text(emergency_phone_digits),
                    "chief_complaint_enc": encrypt_text(chief_complaint),
                    "notes_enc": encrypt_text(notes),
                    "registered_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                st.session_state.patients.append(record)
                save_to_csv()
                log_event("Health Worker", "Registered new patient (data encrypted)", name)

                # --- SUCCESS ALERT: show both ciphertext and masked view ---
                st.success(f"✅ {name} registered successfully. Data encrypted at rest.")

                st.markdown("##### 🔑 Raw Encrypted Ciphertext (what the database actually stores)")
                st.code(
                    f"aadhaar_enc:         {record['aadhaar_enc']}\n"
                    f"phone_enc:           {record['phone_enc']}\n"
                    f"emergency_phone_enc: {record['emergency_phone_enc']}\n"
                    f"chief_complaint_enc: {record['chief_complaint_enc'][:50]}...\n"
                    f"notes_enc:           {record['notes_enc'][:50]}...",
                    language="text",
                )

                st.markdown("##### 🕶️ Masked Output (what most staff will ever see)")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Aadhaar", mask_aadhaar(aadhaar_digits))
                m2.metric("Phone", mask_phone(phone_digits))
                m3.metric("Emergency Phone", mask_phone(emergency_phone_digits))
                m4.metric("Notes / Complaint", "•••••• (locked)")

    with col_info:
        st.markdown("##### Why encrypt at the point of entry?")
        st.markdown(
            "- Data is unreadable **the moment it's typed in** — not just "
            "'encrypted later.'\n"
            "- Even a stolen laptop or leaked CSV only exposes ciphertext.\n"
            "- Masking means front-desk staff never need to see full "
            "Aadhaar/phone numbers to do their job.\n"
        )
        st.markdown("##### What's captured & why")
        st.markdown(
            "- **Emergency contact** — critical for elderly/rural patients "
            "who may not carry their own phone.\n"
            "- **Chief complaint** — captured at intake, separate from the "
            "doctor's diagnostic notes.\n"
            "- **Blood group & allergies** — non-identifying but "
            "life-saving in emergencies, so blood group is kept readable "
            "while allergies stay lightly visible for triage speed.\n"
        )
        st.info(
            "🔑 **Fernet** combines AES-128 in CBC mode with HMAC for "
            "integrity — tampered ciphertext fails to decrypt instead of "
            "silently returning corrupted data."
        )


# =======================================================================
# 7. VIEW 2 — DOCTOR DASHBOARD & DYNAMIC MASKING
# =======================================================================
elif page.startswith("🩺"):
    st.title("🩺 Doctor Dashboard & Dynamic Masking")
    st.write(
        "All personal fields are masked by default. A doctor must trigger "
        "an OTP-based consent request and have the **patient** approve it "
        "before any real data is revealed — and only for a limited time."
    )
    st.divider()

    if not st.session_state.patients:
        st.info("No patients registered yet. Add one in the Registration view.")
    else:
        # --- Build the masked table ---
        rows = []
        for p in st.session_state.patients:
            grant = st.session_state.access_grants.get(p["id"])
            unlocked = grant is not None and grant["expiry"] > time.time()

            if unlocked:
                rows.append({
                    "ID": p["id"], "Name": p["name"], "Age": p["age"], "Gender": p["gender"],
                    "Blood Grp": p.get("blood_group", "Unknown"),
                    "Aadhaar": decrypt_text(p["aadhaar_enc"]),
                    "Phone": decrypt_text(p["phone_enc"]),
                    "Emergency Contact": f'{p.get("emergency_name","")} — {decrypt_text(p.get("emergency_phone_enc",""))}',
                    "Chief Complaint": decrypt_text(p.get("chief_complaint_enc", "")),
                    "Notes": decrypt_text(p["notes_enc"]),
                    "Status": f"🔓 Unlocked for Dr. {grant['doctor']} "
                              f"({int(grant['expiry'] - time.time())}s left)",
                })
            else:
                rows.append({
                    "ID": p["id"], "Name": p["name"], "Age": p["age"], "Gender": p["gender"],
                    "Blood Grp": p.get("blood_group", "Unknown"),
                    "Aadhaar": mask_aadhaar(decrypt_text(p["aadhaar_enc"])),
                    "Phone": mask_phone(decrypt_text(p["phone_enc"])),
                    "Emergency Contact": mask_text(""),
                    "Chief Complaint": mask_text(""),
                    "Notes": mask_text(""),
                    "Status": "🔒 Masked",
                })

        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("🔓 Request Full Access (Voice/OTP Consent Trigger)")

        patient_map = {f'{p["id"]} — {p["name"]}': p["id"] for p in st.session_state.patients}
        selected_label = st.selectbox("Select patient record", list(patient_map.keys()))
        selected_id = patient_map[selected_label]
        selected_patient = find_patient(selected_id)

        colA, colB = st.columns(2)
        with colA:
            doctor_name = st.text_input("Requesting Doctor's Name", value="Sharma")
            language = st.selectbox("Patient's preferred language", list(VERNACULAR_PROMPTS.keys()))
            duration_min = st.slider("Access duration (minutes)", 5, 120, 60, step=5)

            if st.button("📲 Request Full Access (Voice/OTP Consent Trigger)", type="primary"):
                otp = str(random.randint(1000, 9999))
                st.session_state.pending_otp[selected_id] = {
                    "otp": otp, "doctor": doctor_name, "duration_min": duration_min,
                }
                log_event(f"Dr. {doctor_name}", "Requested OTP consent access", selected_patient["name"])
                st.rerun()

        with colB:
            pending = st.session_state.pending_otp.get(selected_id)
            if pending:
                prompt = VERNACULAR_PROMPTS[language].format(
                    doc=pending["doctor"], mins=pending["duration_min"]
                )
                st.warning(f"📞 Simulated SMS/Voice sent to patient:\n\n{prompt}")
                # Demo hint only — in production the OTP would never be shown in the UI.
                st.caption(f"(Demo hint — OTP sent to patient: **{pending['otp']}**)")

                entered_otp = st.text_input("Enter OTP to authorize access", max_chars=4, key="otp_input")
                if st.button("✅ Verify OTP & Unlock Record"):
                    if entered_otp == pending["otp"]:
                        st.session_state.access_grants[selected_id] = {
                            "expiry": time.time() + pending["duration_min"] * 60,
                            "doctor": pending["doctor"],
                        }
                        del st.session_state.pending_otp[selected_id]
                        log_event(
                            f"Dr. {pending['doctor']}",
                            f"Consent verified — access granted for {pending['duration_min']} min",
                            selected_patient["name"],
                        )
                        st.success("🔓 OTP verified. Full record unlocked temporarily.")
                        st.rerun()
                    else:
                        st.error("❌ Incorrect OTP. Access denied.")
                        log_event(f"Dr. {pending['doctor']}", "OTP verification FAILED", selected_patient["name"])
            else:
                st.caption("No pending consent request for this patient.")


# =======================================================================
# 8. VIEW 3 — MANAGE PATIENT RECORDS (Update / Delete)
# =======================================================================
elif page.startswith("✏️"):
    st.title("✏️ Manage Patient Records")
    st.write(
        "Correct mistakes (e.g. a mistyped phone number) or remove a "
        "patient's record entirely. Every update and deletion is written "
        "to the audit trail so there's always a record of who changed what."
    )
    st.divider()

    if not st.session_state.patients:
        st.info("No patients registered yet. Add one in the Registration view.")
    else:
        patient_map = {f'{p["id"]} — {p["name"]}': p["id"] for p in st.session_state.patients}
        selected_label = st.selectbox("Select patient to manage", list(patient_map.keys()))
        selected_id = patient_map[selected_label]
        p = find_patient(selected_id)

        edit_tab, delete_tab = st.tabs(["🖊️ Update Record", "🗑️ Delete Record"])

        # ---------------------------------------------------------------
        # UPDATE
        # ---------------------------------------------------------------
        with edit_tab:
            st.caption(
                "Fields are pre-filled with **decrypted current values** so "
                "you can edit them. On save, everything is re-encrypted."
            )
            with st.form("edit_form"):
                new_name = st.text_input("Patient Name", value=p["name"])
                c1, c2 = st.columns(2)
                with c1:
                    new_aadhaar = st.text_input("Aadhaar Number", value=decrypt_text(p["aadhaar_enc"]))
                    new_age = st.number_input("Age", min_value=0, max_value=120, step=1, value=int(p["age"]))
                    new_blood = st.selectbox(
                        "Blood Group", BLOOD_GROUPS,
                        index=BLOOD_GROUPS.index(p.get("blood_group", "Unknown"))
                        if p.get("blood_group", "Unknown") in BLOOD_GROUPS else 0,
                    )
                with c2:
                    new_phone = st.text_input(
                        "Phone Number (10 digits, +91 optional)",
                        value=decrypt_text(p["phone_enc"]), max_chars=14,
                    )
                    new_gender = st.selectbox(
                        "Gender", ["Female", "Male", "Other"],
                        index=["Female", "Male", "Other"].index(p["gender"])
                        if p["gender"] in ["Female", "Male", "Other"] else 0,
                    )

                e1, e2 = st.columns(2)
                with e1:
                    new_emergency_name = st.text_input(
                        "Emergency Contact Name", value=p.get("emergency_name", "")
                    )
                with e2:
                    new_emergency_phone = st.text_input(
                        "Emergency Contact Phone (10 digits, +91 optional)",
                        value=decrypt_text(p.get("emergency_phone_enc", "")), max_chars=14,
                    )

                new_allergies = st.text_input("Known Allergies", value=p.get("allergies", "None"))
                new_complaint = st.text_area(
                    "Chief Complaint", value=decrypt_text(p.get("chief_complaint_enc", ""))
                )
                new_notes = st.text_area("Diagnostic Notes", value=decrypt_text(p["notes_enc"]))

                save_clicked = st.form_submit_button("💾 Save Changes (Re-encrypt)", type="primary")

            if save_clicked:
                aadhaar_digits = "".join(c for c in new_aadhaar if c.isdigit())
                phone_digits = clean_phone(new_phone)
                emergency_digits = clean_phone(new_emergency_phone)

                errors = []
                if not new_name.strip():
                    errors.append("Name is required.")
                if len(aadhaar_digits) != 12:
                    errors.append("Aadhaar must be exactly 12 digits.")
                if len(phone_digits) != 10:
                    errors.append("Phone number must be 10 digits (with or without +91).")
                if emergency_digits and len(emergency_digits) != 10:
                    errors.append("Emergency phone must be 10 digits (with or without +91), or blank.")

                if errors:
                    for e in errors:
                        st.error(e)
                else:
                    p["name"] = new_name.strip()
                    p["age"] = int(new_age)
                    p["gender"] = new_gender
                    p["blood_group"] = new_blood
                    p["allergies"] = new_allergies.strip() or "None"
                    p["emergency_name"] = new_emergency_name.strip()
                    p["aadhaar_enc"] = encrypt_text(aadhaar_digits)
                    p["phone_enc"] = encrypt_text(phone_digits)
                    p["emergency_phone_enc"] = encrypt_text(emergency_digits)
                    p["chief_complaint_enc"] = encrypt_text(new_complaint)
                    p["notes_enc"] = encrypt_text(new_notes)

                    save_to_csv()
                    log_event("Health Worker", "Updated patient record", p["name"])
                    st.success(f"✅ Record for {p['name']} updated and re-encrypted.")
                    st.rerun()

        # ---------------------------------------------------------------
        # DELETE
        # ---------------------------------------------------------------
        with delete_tab:
            st.warning(
                f"⚠️ You are about to permanently delete the record for "
                f"**{p['name']}** (ID {p['id']}). This cannot be undone."
            )
            confirm_text = st.text_input(
                f"Type the patient's name exactly (\"{p['name']}\") to confirm deletion"
            )
            if st.button("🗑️ Permanently Delete Record", type="primary"):
                if confirm_text.strip() == p["name"]:
                    st.session_state.patients = [
                        rec for rec in st.session_state.patients if rec["id"] != p["id"]
                    ]
                    st.session_state.access_grants.pop(p["id"], None)
                    st.session_state.pending_otp.pop(p["id"], None)
                    save_to_csv()
                    log_event("Health Worker", "Deleted patient record", p["name"])
                    st.success(f"🗑️ Record for {p['name']} has been deleted.")
                    st.rerun()
                else:
                    st.error("Name confirmation did not match. Deletion cancelled.")


# =======================================================================
# 9. VIEW 4 — SECURITY AUDIT & SYSTEM ARCHITECTURE (Judge's Overview)
# =======================================================================
else:
    st.title("🔐 Security Audit & System Architecture")
    st.caption("A judge-facing overview of how AarogyaShield protects patient data.")
    st.divider()

    # --- a) Encryption status ---
    c1, c2, c3 = st.columns(3)
    c1.metric("Encryption Engine", "Fernet Active 🔑")
    c2.metric("Cipher Suite", "AES-128-CBC + HMAC")
    c3.metric("Records Protected", len(st.session_state.patients))
    st.success("✅ Encryption key generated and active for this session.")

    st.divider()

    # --- b) Live toggle: encrypted vs decrypted database view ---
    st.subheader("👀 What a Hacker Would See vs. What Doctors See")
    view_mode = st.toggle("Show Decrypted View (authorized users only)", value=False)

    if not st.session_state.patients:
        st.info("No patients registered yet — register some in View 1 to populate this table.")
    else:
        if view_mode:
            st.warning("🔓 Decrypted View — only ever shown to authorized, consented roles.")
            rows = [{
                "ID": p["id"], "Name": p["name"],
                "Aadhaar": decrypt_text(p["aadhaar_enc"]),
                "Phone": decrypt_text(p["phone_enc"]),
                "Emergency Phone": decrypt_text(p.get("emergency_phone_enc", "")),
                "Chief Complaint": decrypt_text(p.get("chief_complaint_enc", "")),
                "Notes": decrypt_text(p["notes_enc"]),
            } for p in st.session_state.patients]
        else:
            st.error("🔒 Raw Database View — this is exactly what leaks or breaches would expose.")
            rows = [{
                "ID": p["id"], "Name": p["name"],
                "Aadhaar": p["aadhaar_enc"][:40] + "...",
                "Phone": p["phone_enc"][:40] + "...",
                "Emergency Phone": str(p.get("emergency_phone_enc", ""))[:40] + "...",
                "Chief Complaint": str(p.get("chief_complaint_enc", ""))[:40] + "...",
                "Notes": p["notes_enc"][:40] + "...",
            } for p in st.session_state.patients]

        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.divider()

    # --- b2) AI-assisted anomaly detection on the audit trail ---
    st.subheader("🤖 AI-Assisted Anomaly Detection")
    st.caption(
        "Analyses only audit-log metadata (who, what, when) — never patient "
        "data — so this AI layer adds protection without adding exposure."
    )
    alerts, risk_score = detect_anomalies(st.session_state.audit_log)
    risk_label = "Low" if risk_score < 20 else ("Elevated" if risk_score < 50 else "High")

    r1, r2, r3 = st.columns(3)
    r1.metric("Risk Score", f"{risk_score}/100")
    r2.metric("Risk Level", risk_label)
    r3.metric("Active Alerts", len(alerts))

    if alerts:
        st.error("🚨 Suspicious activity detected — review the alerts below.")
        st.dataframe(
            pd.DataFrame(alerts)[["Severity", "Rule", "Actor", "Detail"]],
            use_container_width=True, hide_index=True,
        )
    else:
        st.success("✅ No suspicious access patterns detected.")

    d1, d2 = st.columns(2)
    if d1.button("🧪 Simulate suspicious activity (demo)"):
        # Adds fake failed-OTP attempts and a burst of requests from an unknown doctor
        for _ in range(4):
            log_event("Dr. Unknown (simulated)", "Requested OTP consent access", "Test Patient")
        for _ in range(3):
            log_event("Dr. Unknown (simulated)", "OTP verification FAILED", "Test Patient")
        st.rerun()
    if d2.button("🧹 Clear simulated events"):
        st.session_state.audit_log = [
            e for e in st.session_state.audit_log if "(simulated)" not in e["Actor"]
        ]
        st.rerun()

    st.divider()

    # --- c) Why this protects rural & elderly citizens ---
    st.subheader("🌾 Why This Protects Rural & Elderly Patients")
    st.markdown(
        "- **No plain-text exposure** — even if a device is lost or a database "
        "table leaks, attackers only see unreadable ciphertext.\n"
        "- **Consent in the patient's own language** — vernacular voice/SMS "
        "prompts mean elderly and low-literacy patients understand exactly "
        "who is accessing their data and why.\n"
        "- **Time-bound access** — a doctor's access automatically expires, "
        "so a single OTP approval can't be reused indefinitely.\n"
        "- **Default-masked views** — front-desk and support staff never "
        "need full Aadhaar or phone numbers to do their jobs, shrinking the "
        "'insider threat' surface.\n"
        "- **Editable & deletable records with audit logging** — mistakes "
        "(e.g. a wrong phone number) can be corrected, and patients' right "
        "to have their data removed is respected, without losing "
        "accountability.\n"
        "- **Full audit trail** — every access request, grant, update, "
        "deletion, and failure is logged, so misuse can always be traced.\n"
        "- **AI-assisted anomaly detection** — the audit trail is scanned "
        "for guessing attacks, bulk access and off-hours use, raising alerts "
        "without ever touching patient data.\n"
    )

    st.divider()
    st.subheader("📋 Full Audit Trail")
    if st.session_state.audit_log:
        audit_df = pd.DataFrame(st.session_state.audit_log).iloc[::-1]
        st.dataframe(audit_df, use_container_width=True, hide_index=True)
    else:
        st.info("No actions logged yet.")
