rule Win_Trojan_Gravanda_1
{
strings:
	$a0 = { 84019a0d0022015589e581ec00018dbe00ff165731c0509a05098401bf8a061e57b84f00509aa7098401b00050 }


condition:
	$a0
}