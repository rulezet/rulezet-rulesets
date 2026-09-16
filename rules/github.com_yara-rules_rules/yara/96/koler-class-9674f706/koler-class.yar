rule koler_class : android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.A class"

	strings:
		$0 = "FIND_VALID_DOMAIN"
		$a = "6589y459"
		
	condition:
		$0 and $a
		
}