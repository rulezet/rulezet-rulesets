rule Win_Trojan_Mosquito_3
{
strings:
	$a0 = { fd77232d030089862802b440b962018d960001cd21b80042e84800b440b904008d962702cd21 }


condition:
	$a0
}