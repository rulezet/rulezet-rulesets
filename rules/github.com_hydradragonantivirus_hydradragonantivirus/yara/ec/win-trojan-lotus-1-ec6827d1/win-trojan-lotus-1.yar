rule Win_Trojan_Lotus_1
{
strings:
	$a0 = { 6efa83ed031e06813e0000cd207403e9d5dce82509b8ad0b50584c4c5b39d87502eb03e81409b86930cd2181 }


condition:
	$a0
}