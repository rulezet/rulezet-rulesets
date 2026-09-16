rule Win_Trojan_BW_9
{
strings:
	$a0 = { fec4fec5fec6fec7fec8fec9fecafecbfeccfecdfecefecfd0c8d0c9d0cad0cbd0ccd0cdd0ced0 }


condition:
	$a0
}