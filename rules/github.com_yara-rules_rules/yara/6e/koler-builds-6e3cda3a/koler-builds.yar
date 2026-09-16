rule koler_builds : android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.A builds"

	strings:
		$0 = "buildid"
		$a = "DCEF055EEE3F76CABB27B3BD7233F6E3"
		$b = "C143D55D996634D1B761709372042474"
		
	condition:
		$0 and ($a or $b)
		
}