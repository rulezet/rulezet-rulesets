rule Win_Trojan_Bancos_704
{
strings:
	$a0 = { 16d86385f73d7b7f0898f5d2b0fd0a73bfeae760ce8b164d23a96cbb60b474d2dbe94094beecb89c6a4948cc9343997915d1028305dffc265ef6584c4a6c67e565 }


condition:
	$a0
}