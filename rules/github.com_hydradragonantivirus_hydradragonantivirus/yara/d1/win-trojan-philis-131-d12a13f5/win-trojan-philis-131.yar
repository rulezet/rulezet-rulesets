rule Win_Trojan_Philis_131
{
strings:
	$a0 = { 81f3ec32000081f3ec3200006081fb3681000074027500e80000000056f7d65e }


condition:
	$a0
}