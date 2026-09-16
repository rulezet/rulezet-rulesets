rule Win_Trojan_SillyRC_6
{
strings:
	$a0 = { b82135cd21891e94018cc3891e9601681000078bfe26803d60b99800607410fcf3a4061fb425ba4501cd21b003cd21 }


condition:
	$a0
}