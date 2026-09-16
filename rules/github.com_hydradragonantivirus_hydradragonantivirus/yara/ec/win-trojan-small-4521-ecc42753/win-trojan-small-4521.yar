rule Win_Trojan_Small_4521
{
strings:
	$a0 = { 42008b09ffd101d5e84400000089e951e82c00000055e83f00000089e15029e15801cd89ef }


condition:
	$a0
}