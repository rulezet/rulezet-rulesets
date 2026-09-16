rule koler_D : android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.D class"

	strings:
		$0 = "ZActivity"
		$a = "Lcom/android/zics/ZRuntimeInterface"
		
	condition:
		($0 and $a)
		
}