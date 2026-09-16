rule Win_Trojan_PhPen_5
{
strings:
	$a0 = { 636d642e657865 }

	$a1 = { 63757272656e7476657273696f6e5c72756e5c6261636b646f6f72 }

	$a2 = { 6d69782e646c6c }


condition:
	$a0 and $a1 and $a2
}