rule Win_Trojan_Krnl_2
{
strings:
	$a0 = { 1efc[1-10]8cc88ed8[1-10]8ec08d06[1-10]8bf08bf8[1-10]b9ec07ac04??aae2fa }


condition:
	$a0
}