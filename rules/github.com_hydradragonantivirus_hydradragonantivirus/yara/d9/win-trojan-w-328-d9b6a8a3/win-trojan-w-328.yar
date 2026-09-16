rule Win_Trojan_W_328
{
strings:
	$a0 = { 570f014c24fe5fdf2fe830000000df7ff8bbc112f7bf813b3fed08007f1f68f2100000df6e26cd200d004000df7e265997f3a481efa21000002bfb893bcf }


condition:
	$a0
}