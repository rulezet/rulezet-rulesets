rule Win_Trojan_Small_4416
{
strings:
	$a0 = { bf0011400083c9fff2aef7d12bf98bf78bfa8bd183c9fff2ae8bca4fc1e902f3a58bca83e103f3a4e8f3fdffff }


condition:
	$a0
}