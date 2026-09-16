rule Win_Trojan_Helloween_4
{
strings:
	$a0 = { 8e06120033ffb96005fc56f3a45e06 }


condition:
	$a0
}