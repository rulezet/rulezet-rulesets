rule Win_Trojan_Small_159
{
strings:
	$a0 = { 33c08ed8813e720422227427c706720422221fb82135cd212e891ea7012e8c06a901ba4b01b82125cd21baad0181c2 }


condition:
	$a0
}