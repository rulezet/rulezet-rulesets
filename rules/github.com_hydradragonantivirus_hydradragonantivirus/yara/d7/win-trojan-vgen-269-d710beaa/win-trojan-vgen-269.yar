rule Win_Trojan_VGEN_269
{
strings:
	$a0 = { cd213c027302cd20b9ffffeb0690b8004ccd21e2f6b401cd161e06e800005d81eda003e81802e4402e8886e305e8 }


condition:
	$a0
}