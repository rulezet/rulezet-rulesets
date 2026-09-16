rule Win_Trojan_Agent_32823
{
strings:
	$a0 = { 2bb07d7fa7081bc20aec954a904ef4e42e8e1e5d74519feca8a9833c3e190b40d3a685ce346ac8753620fb72c71d1c1a6d038334403e4a55f3e0bd4069c820796a }


condition:
	$a0
}