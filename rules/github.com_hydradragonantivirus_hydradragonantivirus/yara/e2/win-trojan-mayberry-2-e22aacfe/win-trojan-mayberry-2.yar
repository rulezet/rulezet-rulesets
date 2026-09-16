rule Win_Trojan_Mayberry_2
{
strings:
	$a0 = { 013b169d01744481c2990189169a01ba9c01cd21b440b9960190ba0600cd2132c0 }


condition:
	$a0
}