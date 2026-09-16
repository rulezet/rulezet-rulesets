rule Win_Trojan_Problem_7
{
strings:
	$a0 = { 031eb435b021cd21fa2e8c845b032e899c59038cd82e018497002e01848b0048eb0d26803e00004d7543260306 }


condition:
	$a0
}