rule Win_Trojan_Grox_1
{
strings:
	$a0 = { c08ed88ec0be007c8be6fbb80102b90100ba8000bb007ecd1372252681bf77015b47741c2ec606a07d00b80202fe }


condition:
	$a0
}