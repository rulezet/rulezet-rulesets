rule Win_Trojan_AntiExe_1
{
strings:
	$a0 = { 8edfc4164c0089164c038c064e03fa8ed7be007c8be6fb1e5656a1130448a31304b106d3e08e }


condition:
	$a0
}