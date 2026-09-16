rule Win_Trojan_Digger_3
{
strings:
	$a0 = { d18bdc33d28ed2ba14008be2518be38ed15b3d9b1b74122e8b3e010181c703012e813e01018400741753b91505bb }


condition:
	$a0
}