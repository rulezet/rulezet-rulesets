rule Win_Trojan_Kittykat_1
{
strings:
	$a0 = { 4000ff3524104000ff15693040006a0068800000006a026a006a0068000000c0 }


condition:
	$a0
}