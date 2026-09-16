rule Win_Trojan_Gen_240
{
strings:
	$a0 = { 7f005589e531c09a7c027f0031c0a3b6f031c0a3b2f031c0a3b0f0e883f9e848ffe897fa5d31c09ae9007f0000 }


condition:
	$a0
}