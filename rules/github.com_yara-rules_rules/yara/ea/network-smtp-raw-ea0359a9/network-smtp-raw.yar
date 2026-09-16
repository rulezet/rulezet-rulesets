rule network_smtp_raw {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
    condition:
        all of them
}