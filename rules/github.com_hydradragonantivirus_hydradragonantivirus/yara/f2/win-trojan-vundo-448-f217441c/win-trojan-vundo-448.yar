rule Win_Trojan_Vundo_448
{
strings:
	$a0 = { 558beceb3a5a565d5054535e5d58525f58555f6059525d5d59585951515f5c56eb3c525953535459 }


condition:
	$a0
}