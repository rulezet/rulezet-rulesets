rule Win_Trojan_OhOh_1
{
strings:
	$a0 = { 83d200b90002f7f140a3040089160200c606140100ba0001b91f03b440cd217220803e1501 }


condition:
	$a0
}