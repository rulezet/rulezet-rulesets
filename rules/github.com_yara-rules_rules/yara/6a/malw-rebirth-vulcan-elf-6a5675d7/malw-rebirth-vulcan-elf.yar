rule MALW_Rebirth_Vulcan_ELF {
	meta:
		description = "Detects Rebirth Vulcan variant a torlus NextGen MALW"
		description = "Just adjust or omit below two strings for next version they code :) @unixfreaxjp"
		date = "2018-01-21"
	strings:
                $spec01 = "vulcan.sh" fullword nocase wide ascii
		$spec02 = "Vulcan" fullword nocase wide ascii
	condition:
                all of them
		and is__elf
		and is__str_Rebirth_gen3
		and is__hex_Rebirth_gen3
		and is__bot_Rebirth_gen3
		and filesize < 300KB 
}