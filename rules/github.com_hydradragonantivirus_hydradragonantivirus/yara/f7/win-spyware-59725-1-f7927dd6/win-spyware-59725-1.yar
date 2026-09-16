rule Win_Spyware_59725_1
{
strings:
	$a0 = { 558bec81c4c0feffff60837d0c010f85b4 }

	$a1 = { 676f6c645f636f696e }

	$a2 = { 504f53545f55524c }


condition:
	$a0 and $a1 and $a2
}