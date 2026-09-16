rule Win_Trojan_Poseidon_21
{
strings:
	$a0 = { 558bec81eca00b00008b45085356a3c003420033c05766898560f8ffff8d45d4 }

	$a1 = { 8b45cc3905d00342007e098b5d14ffd3eb0233c05f5e5bc9c21000 }


condition:
	$a0 and $a1
}