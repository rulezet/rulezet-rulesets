rule Win_Trojan_AntiMIT_1
{
strings:
	$a0 = { 018a260501eb11ac32c4aae2fab419cd218af0b40ecd }


condition:
	$a0
}