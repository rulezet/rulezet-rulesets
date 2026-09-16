rule Win_Trojan_Grog_29
{
strings:
	$a0 = { cd21723093b90400ba4b0103d58bf2b43fcd21adad }


condition:
	$a0
}