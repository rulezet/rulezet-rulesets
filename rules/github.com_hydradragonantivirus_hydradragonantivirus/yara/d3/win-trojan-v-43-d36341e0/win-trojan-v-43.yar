rule Win_Trojan_V_43
{
strings:
	$a0 = { b409ba2f01cd21b82135cd21065333c08ec0be4001bf0002b98001f3a48ed88f058f4502ba0002b82125cd21c356 }


condition:
	$a0
}