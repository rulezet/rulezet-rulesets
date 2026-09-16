rule Win_Trojan_Crawler_2
{
strings:
	$a0 = { 55308d1ef304e89802bdd454bdeb7a5188e533fe809a9ad8860c33d88e1834ec7755c3f18871059811d9b6b533dc }


condition:
	$a0
}