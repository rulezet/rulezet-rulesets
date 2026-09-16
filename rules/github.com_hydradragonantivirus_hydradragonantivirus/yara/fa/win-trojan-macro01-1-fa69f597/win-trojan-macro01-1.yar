rule Win_Trojan_Macro01_1
{
strings:
	$a0 = { 4309e92e8916440932c0e846ffba4309b440b90300cd21ba4d09b90700b440cd212efe0670 }


condition:
	$a0
}