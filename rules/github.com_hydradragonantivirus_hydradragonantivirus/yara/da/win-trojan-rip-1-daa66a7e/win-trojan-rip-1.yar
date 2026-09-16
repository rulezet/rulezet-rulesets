rule Win_Trojan_RiP_1
{
strings:
	$a0 = { b200bedc018f04b440b90400badb01e86effe97700ba0800e8990089f2e887008b043d20007565 }


condition:
	$a0
}