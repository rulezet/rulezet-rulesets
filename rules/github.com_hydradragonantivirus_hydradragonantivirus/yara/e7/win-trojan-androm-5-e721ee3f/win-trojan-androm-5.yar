rule Win_Trojan_Androm_5
{
strings:
	$a0 = { e81bf6ffff6891c54000e815dcffff6a4e68679d4000683e6a4000e89bbaffff6a006a18ff153cf1400083c41833c0c3 }


condition:
	$a0
}