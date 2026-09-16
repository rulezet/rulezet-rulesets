rule Win_Trojan_Mailskinner_1
{
strings:
	$a0 = { 5c4d61696c536b696e6e65725c4d61696c536b696e6e65722e657865 }

	$a1 = { 5c43757272656e7456657273696f6e5c52756e }


condition:
	$a0 and $a1
}