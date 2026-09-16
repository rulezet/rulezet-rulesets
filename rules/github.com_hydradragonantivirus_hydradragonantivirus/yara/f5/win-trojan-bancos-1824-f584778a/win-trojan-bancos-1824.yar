rule Win_Trojan_Bancos_1824
{
strings:
	$a0 = { ebefa7effc04684ec7f8f82c0a030b8dfe336a81f03963ee5c908cce4c87272d72b05a441d16e00aa2a4c09f07188e048cc37a414bc9fcf31990488481ca0b017f505a272515 }


condition:
	$a0
}