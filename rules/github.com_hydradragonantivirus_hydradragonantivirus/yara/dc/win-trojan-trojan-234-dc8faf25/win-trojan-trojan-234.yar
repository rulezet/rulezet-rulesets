rule Win_Trojan_Trojan_234
{
strings:
	$a0 = { be7e188134443a4646e2f80dd146f764d8bed2443a1c73af38891aa6c0692244b1ac3cfc1a71f765828baa62bd43f7641cc33d }


condition:
	$a0
}