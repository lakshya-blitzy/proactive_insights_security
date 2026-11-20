"""Static-analysis fixture: predictable temporary file name."""
def write_report(contents):
    path = "/tmp/report.txt"
    with open(path, "w") as report:
        report.write(contents)
    return path
