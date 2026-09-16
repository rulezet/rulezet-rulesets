rule Win_Trojan_Vundo_449
{
strings:
	$a0 = { 558beceb3d525150eb4c50605d605d5f5655535b5d52566055545c595959535b505f60515a5f55 }


condition:
	$a0
}