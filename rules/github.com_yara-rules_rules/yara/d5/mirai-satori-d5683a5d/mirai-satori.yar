rule Mirai_Satori {
	meta:
		description = "Detects Mirai Satori MALW"
		date = "2018-01-09"

	strings:
		$hexsts01 = { 63 71 75 ?? 62 6B 77 62 75 }
		$hexsts02 = { 53 54 68 72 75 64 62 }
		$hexsts03 = { 28 63 62 71 28 70 66 73 64 6F 63 68 60 } 

	condition:
		all of them
		and is__elf
		and is__Mirai_gen7
		and is__Mirai_Satori_gen
		and filesize < 100KB 
}