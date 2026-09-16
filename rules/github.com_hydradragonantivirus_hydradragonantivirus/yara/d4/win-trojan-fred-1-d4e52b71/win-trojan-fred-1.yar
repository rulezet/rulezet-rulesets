rule Win_Trojan_Fred_1
{
strings:
	$a0 = { ff741a80fc4e740a80fc4f7405ea0c01cd14e85c00e8 }


condition:
	$a0
}