from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph
import os

REPORT_FOLDER = "reports"

os.makedirs(REPORT_FOLDER, exist_ok=True)


def generate_report(data):

    filename = data["filename"].replace(".", "_") + ".pdf"

    pdf_path = os.path.join(REPORT_FOLDER, filename)

    doc = SimpleDocTemplate(pdf_path)

    styles = getSampleStyleSheet()

    story = []

    story.append(Paragraph("<b>MalGuard AI Malware Scan Report</b>", styles["Title"]))
    story.append(Paragraph("<br/>", styles["Normal"]))

    story.append(Paragraph(f"<b>File Name:</b> {data['filename']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Prediction:</b> {data['prediction']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Confidence:</b> {data['confidence']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Risk Level:</b> {data['risk']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Threat Score:</b> {data['threat_score']}%", styles["Normal"]))
    story.append(Paragraph(f"<b>Entropy:</b> {data['entropy']}", styles["Normal"]))
    story.append(Paragraph(f"<b>SHA256:</b> {data['sha256']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Time:</b> {data['scan_time']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Status:</b> {data['status']}", styles["Normal"]))

    doc.build(story)

    return pdf_path