rule Win_Trojan_Autorun_410
{
strings:
	$a0 = { 558bec6aff6830fd40006818ad400064a1 }

	$a1 = { 5c40007265737369676e616d65 }

	$a2 = { 6f00700065006e }

	$a3 = { 676f746f206c610a64656c }


condition:
	$a0 and $a1 and $a2 and $a3
}