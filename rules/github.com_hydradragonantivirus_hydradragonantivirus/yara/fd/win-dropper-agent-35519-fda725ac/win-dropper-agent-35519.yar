rule Win_Dropper_Agent_35519
{
strings:
	$a0 = { e80a000000e97affffffcccccccccc8b }

	$a1 = { 7279652e657865[0-5]7472756a747972757472 }


condition:
	$a0 and $a1
}