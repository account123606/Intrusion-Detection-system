# logger.py
import datetime

def log_threat(threat_msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {threat_msg}"
    print(log_entry)  # Print to console for debugging

    # Open file with UTF-8 encoding to support emojis and special characters
    with open("ids_log.txt", "a", encoding="utf-8") as log_file:
        log_file.write(log_entry + "\n")