rule Win_Trojan_Vgen_133
{
strings:
	$a0 = { b9d1008714eb1071fa8706840087068400fb1f584aeb09501e33c08ed8ebe9e587144646497403e9d9ffe99001 }


condition:
	$a0
}