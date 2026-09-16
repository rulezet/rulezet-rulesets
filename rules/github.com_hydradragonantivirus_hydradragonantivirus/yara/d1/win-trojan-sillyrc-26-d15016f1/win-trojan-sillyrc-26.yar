rule Win_Trojan_SillyRC_26
{
strings:
	$a0 = { 50e800005eb8fe35cd2181fb0110744aba0110b425cd218cc848812e020000018ed8812e03000001a103008ccb03c38e }


condition:
	$a0
}