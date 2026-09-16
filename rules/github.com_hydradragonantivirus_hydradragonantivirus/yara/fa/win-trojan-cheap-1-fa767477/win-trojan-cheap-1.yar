rule Win_Trojan_Cheap_1
{
strings:
	$a0 = { 77293d0a0072242d03003e8986d701b440b9da008d960401cd21b80042e83d00b440b90400 }


condition:
	$a0
}