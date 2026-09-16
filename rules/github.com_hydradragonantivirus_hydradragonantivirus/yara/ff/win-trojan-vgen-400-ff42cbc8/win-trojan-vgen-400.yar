rule Win_Trojan_VGEN_400
{
strings:
	$a0 = { 5e83ee030e56601e061e560e0ea12c001f33f68ec6bf0002b980018be9f3a48ed9be8400837c02207402a5a5ea }


condition:
	$a0
}