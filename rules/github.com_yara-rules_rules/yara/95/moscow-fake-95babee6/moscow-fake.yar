rule moscow_fake : banker androoid
{
	meta:
	  author = "Fernando Denis"
		reference = "https://koodous.com/ https://twitter.com/fdrg21"
		description = "Moskow Droid Development"
		thread_level = 3
		in_the_wild = true

	strings:
		$string_a = "%ioperator%"
		$string_b = "%imodel%"
		$string_c = "%ideviceid%"
		$string_d = "%ipackname%"
		$string_e = "VILLLLLL"

	condition:
		all of ($string_*)
}