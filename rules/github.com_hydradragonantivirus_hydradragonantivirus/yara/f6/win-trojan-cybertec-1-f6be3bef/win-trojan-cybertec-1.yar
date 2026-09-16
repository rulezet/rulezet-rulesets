rule Win_Trojan_Cybertec_1
{
strings:
	$a0 = { b440ba00fab92802cd21b80042e81900b4408d961f03b90300cd21e81200e962ffe80c00b4 }


condition:
	$a0
}