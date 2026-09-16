rule is__bot_Rebirth_gen3 {
	meta:
		author = "unixfreaxjp"
		date = "2018-01-21"
	strings:
        	$bot01 = "MIRAITEST" fullword nocase wide ascii
        	$bot02 = "TELNETTEST" fullword nocase wide ascii
        	$bot03 = "UPDATE" fullword nocase wide ascii
        	$bot04 = "PHONE" fullword nocase wide ascii
        	$bot05 = "RANGE" fullword nocase wide ascii
		$bot06 = "KILLATTK" fullword nocase wide ascii
		$bot07 = "STD" fullword nocase wide ascii
        	$bot08 = "BCM" fullword nocase wide ascii
		$bot09 = "NETIS" fullword nocase wide ascii
		$bot10 = "FASTLOAD" fullword nocase wide ascii
	condition:
        	6 of them
}