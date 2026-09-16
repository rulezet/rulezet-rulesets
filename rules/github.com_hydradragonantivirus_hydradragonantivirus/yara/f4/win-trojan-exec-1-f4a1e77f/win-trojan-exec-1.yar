rule Win_Trojan_Exec_1
{
strings:
	$a0 = { 6765722cff436f76696e6121fffff3e0cdbaa794a9d3e80eedb39e9caed4d2bda8a58fa2ca }


condition:
	$a0
}