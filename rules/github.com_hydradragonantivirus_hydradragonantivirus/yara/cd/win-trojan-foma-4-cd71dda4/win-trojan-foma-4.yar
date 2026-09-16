rule Win_Trojan_Foma_4
{
strings:
	$a0 = { fc55e85b03e8a0ff1e0e1f897512c745081400c64509008bf70633c08ed8bb0400c43f26ff352e8f441c26c605cf }


condition:
	$a0
}