rule Win_Trojan_Abme_1
{
strings:
	$a0 = { 8b36020181c644028bfe81c7a003b9cf01e80300e92902505352558bee81ed0002ad9356518bf5b9ff00ad3bc37402e2f9b8ff002bc1595eaae2e65d5a5b58c3 }


condition:
	$a0
}