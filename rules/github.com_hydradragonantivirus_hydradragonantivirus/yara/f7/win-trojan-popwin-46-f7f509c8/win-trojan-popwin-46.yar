rule Win_Trojan_Popwin_46
{
strings:
	$a0 = { 25282a516eb82161c432a832a4293d16968a2f3de05a51c6adf13c78f1db03ae37f79dbde4b0dd70c03a79cefa0342e3d9d5d3dd941cddb83667a613c37b19c7260ca26b4bc4bca8ac1e0bcf4a28c199 }


condition:
	$a0
}