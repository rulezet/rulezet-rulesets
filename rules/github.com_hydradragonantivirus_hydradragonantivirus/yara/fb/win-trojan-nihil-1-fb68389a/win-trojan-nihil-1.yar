rule Win_Trojan_Nihil_1
{
strings:
	$a0 = { c6eb35908beccc8bdd368b6ffa8bdd81eb09008bebeb02c6238dbe6a00b9530532d22e8a05eb }


condition:
	$a0
}