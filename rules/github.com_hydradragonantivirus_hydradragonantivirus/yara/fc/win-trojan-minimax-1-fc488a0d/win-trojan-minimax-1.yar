rule Win_Trojan_Minimax_1
{
strings:
	$a0 = { 798d3603018d3e957ae8daff8d168f7ab44ee8ccff8b369a0039ee7207b44fba8000ebeee8c7ff8bceb43fe8b3ff }


condition:
	$a0
}