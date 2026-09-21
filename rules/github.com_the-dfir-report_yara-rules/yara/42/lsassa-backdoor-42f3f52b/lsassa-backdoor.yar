rule lsassa_backdoor {
    meta:
        description = "Detects LSASSA Backdoor"
        author = "The DFIR Report, RussianPanda"
		id = "913649fb-e20d-469b-b87c-e1591d43387c"
		reference = "https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion"
        date = "2025-06-24"
        hash = "203eda879dbdb128259cd658b22c9c21c66cbcfa1e2f39879c73b4dafb84c592"
    strings:
        $s1 = "bHNhc3NhJA==" wide ascii
        $s2 = {1F 18 62 0A 06 [1-9] 1F 10 62}
	$s3 = "mscoree.dll"
    condition:
        uint16(0) == 0x5A4D and all of them and filesize < 20KB
}