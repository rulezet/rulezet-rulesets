rule Win_Trojan_Awake_3
{
strings:
	$a0 = { 761e90e80200eb108a965202b934028bfeac32c2aae2fa }


condition:
	$a0
}