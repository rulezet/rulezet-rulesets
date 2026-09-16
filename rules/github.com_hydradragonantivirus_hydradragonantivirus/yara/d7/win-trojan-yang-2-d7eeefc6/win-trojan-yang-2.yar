rule Win_Trojan_Yang_2
{
strings:
	$a0 = { bb0002b8030033d2e82b00be0402e854007302cd182ea113042d04002ea31304b106d3e0 }


condition:
	$a0
}