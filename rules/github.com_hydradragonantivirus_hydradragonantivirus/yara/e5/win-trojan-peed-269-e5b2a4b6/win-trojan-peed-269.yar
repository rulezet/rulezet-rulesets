rule Win_Trojan_Peed_269
{
strings:
	$a0 = { 0f310fa2e8500000005589e5518b7d14b91027000066abc1c807c1c809aa86c4aa5152506a006a00a1 }


condition:
	$a0
}