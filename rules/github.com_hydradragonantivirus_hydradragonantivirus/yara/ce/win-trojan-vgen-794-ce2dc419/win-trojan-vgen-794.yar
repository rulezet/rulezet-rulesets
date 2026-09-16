rule Win_Trojan_VGEN_794
{
strings:
	$a0 = { 100005000050b80000501e1e060e1ffa33c0068ec026c70690008801268c1e920007fbbaf501b41acd21b419cd }


condition:
	$a0
}