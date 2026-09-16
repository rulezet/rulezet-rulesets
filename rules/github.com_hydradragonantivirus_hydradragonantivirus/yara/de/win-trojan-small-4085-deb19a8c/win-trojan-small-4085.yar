rule Win_Trojan_Small_4085
{
strings:
	$a0 = { eb01b8eb39e8000000005b81e30000ffff8b13e803000000ebf7c383c40480fe5a74f7eb008d9b00100000ebebe8d3ffffffeb2a }


condition:
	$a0
}