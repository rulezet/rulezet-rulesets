rule Win_Trojan_Peed_182
{
strings:
	$a0 = { 558bec83ec2c5356570fbede3bc33bc585d94e33fa85c70bfb8bc23bfc0fbed8 }


condition:
	$a0
}