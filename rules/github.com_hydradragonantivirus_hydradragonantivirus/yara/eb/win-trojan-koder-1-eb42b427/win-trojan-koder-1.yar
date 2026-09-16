rule Win_Trojan_Koder_1
{
strings:
	$a0 = { e800005e83ee05b80012cd2f3cff750cbb5446b8001dcd210ac0741f1f8cd88ec02e0184ac062e0384c006051000 }


condition:
	$a0
}