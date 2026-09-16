rule Mirai_Okiru {
	meta:
		description = "Detects Mirai Okiru MALW"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
		date = "2018-01-05"

	strings:
		$hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }
		$hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }
		        
	condition:
    		all of them
		and is__elf
		and is__Mirai_gen7
		and filesize < 100KB 
}