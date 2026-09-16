rule Win_Trojan_QHA_3
{
strings:
	$a0 = { efbeaddec1e902fcf3ab891524a20100a120a20100eb0fa120a20100a3d6860100b8ffffffff5b5f5ec3c38d76005148412028517565626563204861 }


condition:
	$a0
}