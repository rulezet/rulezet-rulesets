rule Win_Trojan_SatanBug_1
{
strings:
	$a0 = { fa1f42f8b9220643bd900143f842316e00424f4ff84542434fb4624e42f542cd21f8424fe2 }


condition:
	$a0
}