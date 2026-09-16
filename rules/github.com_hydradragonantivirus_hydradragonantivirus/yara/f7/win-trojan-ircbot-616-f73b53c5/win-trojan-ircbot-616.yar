rule Win_Trojan_IRCBot_616
{
strings:
	$a0 = { 1e34450c6f8e056addce46f8372ba6c2274481577911b656f538abc89c6cb8614f28eaf78a68bedbc73fcabec84d57a1a0b7d246bcfcf473e423548d0bc7ecf63cfdb68ce1f15ea3b297a50e1de5 }


condition:
	$a0
}