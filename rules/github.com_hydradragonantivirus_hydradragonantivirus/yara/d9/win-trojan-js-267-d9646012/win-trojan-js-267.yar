rule Win_Trojan_JS_267
{
strings:
	$a0 = { 6576616c286e3030302e6f62667573636174652822 }

	$a1 = { 222929 }


condition:
	$a0 and $a1
}