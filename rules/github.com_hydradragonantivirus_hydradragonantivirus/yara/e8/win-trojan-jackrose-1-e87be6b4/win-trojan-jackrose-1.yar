rule Win_Trojan_JackRose_1
{
strings:
	$a0 = { 81ed03015351061ee93001ddac97908d8bdfbc968d9c8a968bdddf9d86dfb59e9c94dfad908c9ad3dfcec6d2cfcdd2 }


condition:
	$a0
}