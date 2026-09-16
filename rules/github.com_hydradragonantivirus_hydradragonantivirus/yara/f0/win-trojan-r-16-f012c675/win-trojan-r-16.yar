rule Win_Trojan_R_16
{
strings:
	$a0 = { fa909090ba4559cd161e0e070e1fe800005d81ed13018dbe1a028db62202e80c00e80900e80600e80300eb0390a5 }


condition:
	$a0
}