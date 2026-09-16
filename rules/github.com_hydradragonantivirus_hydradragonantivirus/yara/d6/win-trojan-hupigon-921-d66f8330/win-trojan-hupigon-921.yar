rule Win_Trojan_Hupigon_921
{
strings:
	$a0 = { 6860004c006a006a00e89a6ef4ff8bd8e8cb6ff4ff3db7000000740485db751053e84a6ef4ffe8a948f4ffe99d000000 }


condition:
	$a0
}