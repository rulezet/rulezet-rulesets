rule is_LNK 
{ 
	meta:
		author = "k3rnelcallz"
		description = "Rule identifying (LNK) shortcut files."
		sha256 = "4f2617a971b9c78c8b215d6cb65525ff56f0633a3bcd381695a19efe08156a04"		
		creation_date = "2-12-25"
		last_modified = "2-12-25"
		source = "Malwarebazaar"
		category = "Info"

	strings:
		$lnk = {4C 00 00 00 01 14 02}

	condition:
		$lnk at 0
}