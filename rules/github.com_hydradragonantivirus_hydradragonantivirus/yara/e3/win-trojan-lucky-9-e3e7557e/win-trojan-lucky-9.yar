rule Win_Trojan_Lucky_9
{
strings:
	$a0 = { 33d2b41acd21b74e93b92000ba390103d61e0e1fcd211f7310e9cf008cc80500208ed8b44fcd21ebeea1 }


condition:
	$a0
}