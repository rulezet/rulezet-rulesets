rule Win_Trojan_Bancos_883
{
strings:
	$a0 = { dcf4185ce4b780e199bb0a8746e9db8f56ed7188201478d036cb9afeec89c6a2114e8f00db02dc0b503199dd4651f049d296141973a1aabe37d44c6bd6d7e58e99 }


condition:
	$a0
}