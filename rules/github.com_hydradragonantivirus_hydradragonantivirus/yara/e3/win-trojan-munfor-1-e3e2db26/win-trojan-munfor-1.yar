rule Win_Trojan_Munfor_1
{
strings:
	$a0 = { ab08ff0360d75533e9a46a7c03e02548d3740d5f87859293ae7ea9034d75cb692d496e6660eec26a610c76f45c61dbec }


condition:
	$a0
}