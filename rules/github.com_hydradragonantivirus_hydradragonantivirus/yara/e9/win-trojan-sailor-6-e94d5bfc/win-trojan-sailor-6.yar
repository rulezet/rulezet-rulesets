rule Win_Trojan_Sailor_6
{
strings:
	$a0 = { e800001e068bec8b5e048beb81ed4406b3b0b82301cd133d012374070e070e1fe84bfb071f582e80 }


condition:
	$a0
}