rule Win_Trojan_Vengence_6
{
strings:
	$a0 = { 8cc88ed8ba6801b44ecd217259ba9e0089160202b8023dcd }


condition:
	$a0
}