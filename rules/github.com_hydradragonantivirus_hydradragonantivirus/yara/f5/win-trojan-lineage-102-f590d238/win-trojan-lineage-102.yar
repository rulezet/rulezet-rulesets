rule Win_Trojan_Lineage_102
{
strings:
	$a0 = { 7d381bd2b3a5c502a9bd2aab2418c3b1ac84c52722795e31dc05648747bf32d446de64a58e96b00fc00430ab8b9f6b5c667b1fc802a577aee1846e6cb4fea41f89ad9509 }


condition:
	$a0
}