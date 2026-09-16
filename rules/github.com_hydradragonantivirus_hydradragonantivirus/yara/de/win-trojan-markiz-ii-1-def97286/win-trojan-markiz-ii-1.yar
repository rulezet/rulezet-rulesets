rule Win_Trojan_Markiz_II_1
{
strings:
	$a0 = { 521e560657e85102ba4000ec86e0ec2ea361028cd80510002e010685032e010687038cc8fa8ed88ec0fbbe8303 }


condition:
	$a0
}