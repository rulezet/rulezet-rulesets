rule Win_Trojan_Czimoz_1
{
strings:
	$a0 = { 4e655f6d73672e4174746163686d656e74732e4164642052616e646f6d66696c657a }


condition:
	$a0
}