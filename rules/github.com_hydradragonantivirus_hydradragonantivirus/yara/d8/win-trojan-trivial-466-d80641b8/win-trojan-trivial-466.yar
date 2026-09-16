rule Win_Trojan_Trivial_466
{
strings:
	$a0 = { 018d9e1501b92200311783c302e2f9b9020051b44ee907006d61696e6d616eb90000ba5001cd217217b8023dba }


condition:
	$a0
}