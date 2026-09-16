rule Win_Trojan_V_11
{
strings:
	$a0 = { 730233c0894606b80142b9ffffbaf8ffcd21b4408bd5b90800cd218bbe3202578bd7e82900 }


condition:
	$a0
}