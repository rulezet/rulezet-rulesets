rule Win_Trojan_Catfish_701BB_1
{
strings:
	$a0 = { ed0300e9a900bb210003ddb941012e8a17d0ca2e881743e2f5e9 }


condition:
	$a0
}