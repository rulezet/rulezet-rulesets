rule Win_Trojan_VGEN_727
{
strings:
	$a0 = { f545ccf5f5fbf5f9cef94dcc90fb9045f9ccf5cef84d45f945bfae05fbf9fa90fafc90fc4d45b96009fbce45f845 }


condition:
	$a0
}