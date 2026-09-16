rule Win_Trojan_Mosquito_5
{
strings:
	$a0 = { 803e39030774f5cd21e882fcfa33c08ec02ea1 }


condition:
	$a0
}