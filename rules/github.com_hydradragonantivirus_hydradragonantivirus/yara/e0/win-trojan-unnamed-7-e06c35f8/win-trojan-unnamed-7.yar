rule Win_Trojan_Unnamed_7
{
strings:
	$a0 = { 5601b90800cd21813e5601ff267509813e5a01ffe07501c3c3b457b000cd21724a89161b01 }


condition:
	$a0
}