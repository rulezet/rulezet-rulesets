import "pe"
rule NoobyProtectSE1x : Nooby
{
	meta:
		author="_pusher_"
		date = "2016-07"
	strings:
								$a0 = "\x00\x00\x00NoobyProtect SE 1." ascii nocase
				$a1 = { 74 06 80 33 20 43 E2 FA 83 C4 04 59 5B 9D }
	condition:
		$a0 at pe.entry_point+0x02 or
		$a1
		}