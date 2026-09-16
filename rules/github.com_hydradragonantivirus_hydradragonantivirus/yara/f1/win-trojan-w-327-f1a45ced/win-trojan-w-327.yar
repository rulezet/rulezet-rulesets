rule Win_Trojan_W_327
{
strings:
	$a0 = { 570f014c24fe5fdf2fe82d000000df7ff8bbc112f7bf803b0f751f6800200000df6e23cd200d004000df7e235997f3a481efb31f00002bfb893bcf }


condition:
	$a0
}