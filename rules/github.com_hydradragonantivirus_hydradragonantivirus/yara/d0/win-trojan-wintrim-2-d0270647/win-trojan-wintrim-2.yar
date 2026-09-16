rule Win_Trojan_Wintrim_2
{
strings:
	$a0 = { 492a52494d530f07f08f850e556e6b6e6f776e17c044ae33d242fa749d05bbe10010756dc71b73c1bebd84130e9353415049 }


condition:
	$a0
}