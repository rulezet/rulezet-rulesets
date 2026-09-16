rule Win_Trojan_SillyC_215
{
strings:
	$a0 = { 215a81ea8a01b91f02b440cd2181c28a0152b80157bae8b9cd21b43ecd215a29c0501ffa2e8b84 }


condition:
	$a0
}