rule Win_Trojan_Vienna_79
{
strings:
	$a0 = { 213c017d02eb4a3c017746eb00b202b405b680b500cd13b9140051e80a00b90040e2fe59e2f4eb }


condition:
	$a0
}