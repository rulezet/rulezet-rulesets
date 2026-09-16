rule Win_Trojan_Qhost_81
{
strings:
	$a0 = { 34312e3138302e313938204155544f2e5345415243482e4d534e }


condition:
	$a0
}