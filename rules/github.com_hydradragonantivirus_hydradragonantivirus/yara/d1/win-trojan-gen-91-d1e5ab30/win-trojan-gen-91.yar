rule Win_Trojan_Gen_91
{
strings:
	$a0 = { bb407d8a0724034001c04801c38b078ec0be497db8050050b0005089f331d28a37fec38b0f }


condition:
	$a0
}