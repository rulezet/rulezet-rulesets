rule Win_Trojan_VGEN_736
{
strings:
	$a0 = { 0d012e8a8468032e8c84850350061e0e0e071fffb46403ffb46603ffb46003ffb46203ffb46903ffb46b038d94cc03 }


condition:
	$a0
}