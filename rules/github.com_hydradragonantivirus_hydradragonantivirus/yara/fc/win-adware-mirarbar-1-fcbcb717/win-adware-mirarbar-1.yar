rule Win_Adware_Mirarbar_1
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d000d031000eb2683fe0174 }

	$a1 = { 4261722e444c4c }


condition:
	$a0 and $a1
}