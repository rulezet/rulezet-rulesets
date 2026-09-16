rule Win_Trojan_Delwin_43
{
strings:
	$a0 = { 636f707920633a5c }

	$a1 = { 5c2a2e65786520633a5c6368616f735c2a2e657865[0-76]64656c20633a5c77696e6e745c2a2e646c6c }


condition:
	$a0 and $a1
}