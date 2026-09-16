rule Win_Trojan_Asmodeous_7
{
strings:
	$a0 = { 730cfdfc0e1fb9bf0051b908008a17525ad0d2e80c0046e2f85943e2ec1ffc535bc373088a0486841d }


condition:
	$a0
}