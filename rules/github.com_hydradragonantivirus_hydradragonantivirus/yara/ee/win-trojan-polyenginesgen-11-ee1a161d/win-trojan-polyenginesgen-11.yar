rule Win_Trojan_PolyEngineSGen_11
{
strings:
	$a0 = { 09ba6001cd21b8c003c1e8048ccb03d88ec3b9320051b43c33c9ba5801cd2150e5402501008bd8b92b00ba9101bd00 }


condition:
	$a0
}