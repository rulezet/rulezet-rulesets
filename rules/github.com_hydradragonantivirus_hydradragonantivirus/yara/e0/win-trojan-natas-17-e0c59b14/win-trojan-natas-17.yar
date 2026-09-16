rule Win_Trojan_Natas_17
{
strings:
	$a0 = { 8d1634b2f9f58beb81d28081b84309c7c7e6c081ef5bb633f48d2ee8038bca87fb48f889e336115600454509c07e03fbebed }


condition:
	$a0
}