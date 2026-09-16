rule Win_Trojan_KGBKeylog_4
{
strings:
	$a0 = { 7368656c6c6578656375746520226d706b6e6574696e7374616c6c2e657865222c }

	$a1 = { 2f7665727973696c656e74 }


condition:
	$a0 and $a1
}