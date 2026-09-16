rule Win_Trojan_Haxdoor_110
{
strings:
	$a0 = { dc548021a4bbd91743581b0c078ec9c0b1f046e36d72001c8482cd5b1efa2e395f0e7000f295de2fb738ea81faad04e8250c0f1ec00a1fd883008404c9b2df7144917d34 }


condition:
	$a0
}