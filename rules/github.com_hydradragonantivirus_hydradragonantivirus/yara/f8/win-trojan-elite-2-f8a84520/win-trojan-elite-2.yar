rule Win_Trojan_Elite_2
{
strings:
	$a0 = { 8bec83ec31836e0009bacbffe85d008b760083c67a90bf0001a5a58b5600b93f00b44ecd21723abae9ffb8023d }


condition:
	$a0
}