rule webshell_tinyasp {
    meta:
	author = "Jeff Beley"
	hash1 = "1f29905348e136b66d4ff6c1494d6008ea13f9551ad5aa9b991893a31b37e452"
	description = "Detects 24 byte ASP webshell and variations"
	date = "2019-01-09"
	id = "38b1f61b-e506-59b2-9157-d0345431c429"
   strings:
   	$s1 = "Execute Request" ascii wide nocase
   condition:
   	uint16(0) == 0x253c and filesize < 150 and 1 of them
}