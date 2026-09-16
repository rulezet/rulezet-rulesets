rule Win_Trojan_Rat_3
{
strings:
	$a0 = { e8fafee801ffb43fb91800ba8902cd21e8effeb900 }


condition:
	$a0
}