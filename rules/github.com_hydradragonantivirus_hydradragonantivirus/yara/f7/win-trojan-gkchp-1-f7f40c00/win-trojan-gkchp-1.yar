rule Win_Trojan_Gkchp_1
{
strings:
	$a0 = { 8cd8059b008ed8bb2801b9840190a1140131074343e2fa }


condition:
	$a0
}