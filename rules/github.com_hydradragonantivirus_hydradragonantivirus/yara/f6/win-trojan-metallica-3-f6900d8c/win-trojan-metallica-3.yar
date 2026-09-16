rule Win_Trojan_Metallica_3
{
strings:
	$a0 = { 3d74323d6c0074183c4b74353c4374253c56742186 }


condition:
	$a0
}