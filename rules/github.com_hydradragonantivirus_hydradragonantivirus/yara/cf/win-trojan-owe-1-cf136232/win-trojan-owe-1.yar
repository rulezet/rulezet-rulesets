rule Win_Trojan_Owe_1
{
strings:
	$a0 = { ba0003b90501cd2b6140cd2bb43ecd2bba3e00b80143b90700cd2bc5160501b82125cd2beb3c }


condition:
	$a0
}