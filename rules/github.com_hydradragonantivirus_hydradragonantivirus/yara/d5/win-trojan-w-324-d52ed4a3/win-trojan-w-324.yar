rule Win_Trojan_W_324
{
strings:
	$a0 = { 96570f014c24fe5fdf2fe899000000df7ff8bb8c12f7bf807b350f751bdf }


condition:
	$a0
}