rule Win_Trojan_UBIQ2_1
{
strings:
	$a0 = { be0300b80c02b101cd134e740e72f48beb81c331125251ffd3595a1607b80102bb007cb10d }


condition:
	$a0
}