rule Win_Trojan_Agent_34395
{
strings:
	$a0 = { be00????00608dbe00????ff5783cdffeb109090909090908a068807464701db75078b1e83eefc11db72edb80100000001db75078b1e83eefc11db }


condition:
	$a0
}