rule Win_Spyware_4545_1
{
strings:
	$a0 = { 4f505881f0cb0c68014833edb8efead201f7d7 }


condition:
	$a0
}