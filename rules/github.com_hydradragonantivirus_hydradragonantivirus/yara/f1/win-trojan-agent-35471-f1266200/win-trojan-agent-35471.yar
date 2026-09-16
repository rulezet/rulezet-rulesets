rule Win_Trojan_Agent_35471
{
strings:
	$a0 = { 74a873bbd57b52fd6f973a8467 }

	$a1 = { 6e746f736b726e6c2e657865 }


condition:
	$a0 and $a1
}