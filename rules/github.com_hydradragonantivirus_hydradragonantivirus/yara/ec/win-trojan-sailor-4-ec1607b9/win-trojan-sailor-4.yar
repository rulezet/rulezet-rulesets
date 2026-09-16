rule Win_Trojan_Sailor_4
{
strings:
	$a0 = { 5e048beb81ed03002e80be470088745be80200eb560e }


condition:
	$a0
}