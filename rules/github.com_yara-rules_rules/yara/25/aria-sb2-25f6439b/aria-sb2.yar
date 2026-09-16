rule ARIA_SB2
{	meta:
		author = "spelissier"
		description = "Aria SBox 2"
		date = "2020-12"
		reference="http://210.104.33.10/ARIA/doc/ARIA-specification-e.pdf#page=7"
	strings:
		$c0 = { E2 4E 54 FC 94 C2 4A CC 62 0D 6A 46 3C 4D 8B D1 5E FA 64 CB B4 97 BE 2B BC 77 2E 03 D3 19 59 C1 }
	condition:
		$c0
}