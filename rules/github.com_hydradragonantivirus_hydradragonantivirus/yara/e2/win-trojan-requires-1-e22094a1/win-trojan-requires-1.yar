rule Win_Trojan_Requires_1
{
strings:
	$a0 = { b4b3cd213d51907455be02008cd8488ed8836c017a8edd832c7a8b042d }


condition:
	$a0
}