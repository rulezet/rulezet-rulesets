rule Win_Trojan_VCL_28
{
strings:
	$a0 = { b440b903008d952a0390cd21b80242998bca90cd21b440b962028d95030190cd21b801578b4c16 }


condition:
	$a0
}