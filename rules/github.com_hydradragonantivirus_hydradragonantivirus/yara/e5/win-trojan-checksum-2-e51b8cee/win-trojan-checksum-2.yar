rule Win_Trojan_Checksum_2
{
strings:
	$a0 = { 2e03004f832e02004f0bc9740b508cc0408ec0b449cd21 }


condition:
	$a0
}