rule Ransomware : banker android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Ransomware Test 2"
		thread_level = 3
		in_the_wild = true

	strings:

		$strings_a = "!2,.B99^GGD&R-"
		$strings_b = "22922222222222222222Q^SAAWA"
		$strings_c = "t2222222222229222Q^SAAWA"

	

	condition:
		any of ($strings_*)
}