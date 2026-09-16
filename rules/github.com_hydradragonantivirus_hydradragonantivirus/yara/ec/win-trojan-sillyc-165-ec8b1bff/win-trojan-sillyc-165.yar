rule Win_Trojan_SillyC_165
{
strings:
	$a0 = { b44ecd21eb04b44fcd2173123c12750b83fdff7406 }


condition:
	$a0
}