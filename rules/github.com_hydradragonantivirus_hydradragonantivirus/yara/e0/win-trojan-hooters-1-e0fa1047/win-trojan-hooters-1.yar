rule Win_Trojan_Hooters_1
{
strings:
	$a0 = { 28710ee82012bce44d85c004791a6aaea1de1c888a02c42309350303e9f62132ffe9aa84f0cc }


condition:
	$a0
}