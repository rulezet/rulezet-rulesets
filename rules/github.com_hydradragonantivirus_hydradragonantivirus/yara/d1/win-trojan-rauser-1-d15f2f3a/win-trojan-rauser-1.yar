rule Win_Trojan_Rauser_1
{
strings:
	$a0 = { 9c4b05cac24b3dc3c2bcc7f93521316e66283195c4d59873e1ca77f60eeb50c4dc7b3ef9117e8395 }


condition:
	$a0
}