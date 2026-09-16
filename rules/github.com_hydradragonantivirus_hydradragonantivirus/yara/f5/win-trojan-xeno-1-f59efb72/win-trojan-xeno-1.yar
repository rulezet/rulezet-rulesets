rule Win_Trojan_Xeno_1
{
strings:
	$a0 = { b70f0eacab0bbb4d3dcf3cc63cdd8411830bc22ebb4f8411830bb6150fb59f0bc22ebb4dbf0f8411 }


condition:
	$a0
}