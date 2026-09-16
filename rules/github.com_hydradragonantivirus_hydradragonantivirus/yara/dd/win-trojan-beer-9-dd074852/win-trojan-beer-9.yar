rule Win_Trojan_Beer_9
{
strings:
	$a0 = { 1e0660e8b6ffe9aa050000000000000000fae8a7ff2ec606dd01009c1e06600e1fb82435e84601062e8f062d022e }


condition:
	$a0
}