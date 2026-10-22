import csv
import json


def export_report(path, rows):
    if str(path).lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(rows, stream, ensure_ascii=False, indent=2, default=str)
    else:
        with open(path, "w", encoding="utf-8-sig", newline="") as stream:
            if rows:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader()
                for row in rows:
                    # Prevent spreadsheet formula execution when opening untrusted event fields.
                    writer.writerow(
                        {
                            k: "'" + v
                            if isinstance(v, str) and v.startswith(("=", "+", "-", "@", "\t", "\r"))
                            else v
                            for k, v in row.items()
                        }
                    )
