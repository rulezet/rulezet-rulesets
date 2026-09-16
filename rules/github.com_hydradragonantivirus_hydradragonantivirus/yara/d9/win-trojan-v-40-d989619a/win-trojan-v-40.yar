rule Win_Trojan_V_40
{
strings:
	$a0 = { 03b4abcd213c037508eb4890b8000150c3b449cd2172f4b80158bb0200cd21b448bb4000cd2172e350488ec026 }


condition:
	$a0
}