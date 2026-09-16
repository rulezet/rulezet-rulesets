rule Win_Trojan_Sality_1035
{
strings:
	$a0 = { 605385c3fecc4a5a0fabc185c30fc0e703cbc0ca890f }

	$a1 = { 5c75ed01dffcffff2e657865220d4e65774d6f6f6e6c69676874 }


condition:
	$a0 and $a1
}