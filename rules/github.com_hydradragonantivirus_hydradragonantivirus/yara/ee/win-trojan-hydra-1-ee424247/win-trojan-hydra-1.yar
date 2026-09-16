rule Win_Trojan_Hydra_1
{
strings:
	$a0 = { b43db002ba5301b002cd218bd8061fb8003fb9ffffbae002 }


condition:
	$a0
}