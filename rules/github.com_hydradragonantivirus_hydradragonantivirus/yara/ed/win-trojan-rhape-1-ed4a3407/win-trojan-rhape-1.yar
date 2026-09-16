rule Win_Trojan_Rhape_1
{
strings:
	$a0 = { 57bfbb010e579a4e097701bf84061e57bfed010e579ae60277018dbe00fe16578dbe00ff }


condition:
	$a0
}