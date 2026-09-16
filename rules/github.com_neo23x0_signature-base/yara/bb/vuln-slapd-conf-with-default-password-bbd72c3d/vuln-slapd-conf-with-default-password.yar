rule VULN_Slapd_Conf_with_Default_Password {
	meta:
		description = "Detects an openldap slapd.conf with the default password test123"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2022-11-22"
		reference = "https://www.openldap.org/doc/admin21/slapdconfig.html"
		score = 70
		id = "1d1319da-125b-5373-88f1-27a23c85729e"
	strings:
		
		$c1 = { 0A 72 6f 6f 74 70 77 20 7b 53 53 48 41 7d 66 73 41 45 79 78 6c 46 4f 74 76 5a 42 77 50 4c 41 46 36 38 7a 70 55 68 74 68 38 6c 45 52 6f 52 }

	condition:
		filename == "slapd.conf" and 
		any of ($c*)
}