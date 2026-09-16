rule Win_Trojan_Vampiro_7
{
strings:
	$a0 = { 0facf1980fa4c20cf7de66c1e2c4660fbae601e981ffffff }


condition:
	$a0
}