rule Win_Trojan_TerminatorRat_2
{
strings:
	$a0 = { b38cbf8dbfca5034625670bdbfbfe23c7ab73442d5b1e657c5bdbfbf5d46323a9ebebfbfefd7bfbebfbf40eabb363aa3 }


condition:
	$a0
}