rule Win_Trojan_Jumper_3
{
strings:
	$a0 = { eb01e932d2eb01e9b440eb01e9cd21eb01e9b44febb9eb01e990c32a2e636f6d005b547269 }


condition:
	$a0
}