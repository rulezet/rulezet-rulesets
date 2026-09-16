rule Win_Trojan_Bancos_780
{
strings:
	$a0 = { d1c8950bbe0f4705b5762be9a95b84a9f6d2237818df6b3e5a12a35c6b8aeb66f2a6fd4f09cf7026bf04d357c7bcc836821a535cc5d35b86682d2100114bff1769ea471f }


condition:
	$a0
}