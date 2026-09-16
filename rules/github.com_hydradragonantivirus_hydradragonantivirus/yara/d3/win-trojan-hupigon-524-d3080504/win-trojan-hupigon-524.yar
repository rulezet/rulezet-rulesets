rule Win_Trojan_Hupigon_524
{
strings:
	$a0 = { 1223da62db94d7b37c5b1d1bb6fd73564ea57465618053bfa3cca0039d3a9831c83704f431a22fd295e036cfa4ad41511d5787ac1ec4bad31d78ea11e5b4a828ea3ac9b3fb2c3e55d1f2f5aaf260 }


condition:
	$a0
}