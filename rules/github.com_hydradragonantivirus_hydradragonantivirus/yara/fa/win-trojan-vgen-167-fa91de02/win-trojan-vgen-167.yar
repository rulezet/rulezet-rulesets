rule Win_Trojan_VGEN_167
{
strings:
	$a0 = { 01018ae48b5e008ae4438ae481c302018ae4bd00018ae48a57fc8ae48856008ae48a57fd8ae48856018ae48a57fe8a }


condition:
	$a0
}