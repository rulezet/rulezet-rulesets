rule Win_Trojan_Anthrax_5
{
strings:
	$a0 = { ba270451535052cb8ec1b104beb00583c60ead3c80 }


condition:
	$a0
}