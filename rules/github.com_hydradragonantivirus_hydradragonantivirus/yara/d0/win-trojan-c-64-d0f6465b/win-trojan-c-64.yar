rule Win_Trojan_C_64
{
strings:
	$a0 = { 0956490a00202055f89c061e5756525153500efc8cc8ba9b0d03d052ba930652bac30903c28bd80551048edb8e }


condition:
	$a0
}