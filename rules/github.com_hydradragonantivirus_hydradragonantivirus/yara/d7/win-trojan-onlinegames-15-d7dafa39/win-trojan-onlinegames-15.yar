rule Win_Trojan_Onlinegames_15
{
strings:
	$a0 = { f9eb03bf35045781d70a6c0a61f7d75ff7d757f714245fe9a169010081f642 }

	$a1 = { 6d6f636f }


condition:
	$a0 and $a1
}