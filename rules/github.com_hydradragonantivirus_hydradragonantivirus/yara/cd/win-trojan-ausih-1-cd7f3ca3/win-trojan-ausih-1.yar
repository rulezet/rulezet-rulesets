rule Win_Trojan_Ausih_1
{
strings:
	$a0 = { 07bb5c00b44acd218e062c0033c089c1498bf8f2aeae75fb4747893ec301c606c50100b8c054cd213d6606743ac606 }


condition:
	$a0
}