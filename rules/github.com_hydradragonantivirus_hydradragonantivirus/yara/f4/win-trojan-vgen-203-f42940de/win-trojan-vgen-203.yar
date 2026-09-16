rule Win_Trojan_VGEN_203
{
strings:
	$a0 = { 90bd0400cd038dbec802ffd7eb22e9df00992414cd00feebfee38ca7fb2389bff923fad6dcd6dcda8db78323b80525ec21 }


condition:
	$a0
}