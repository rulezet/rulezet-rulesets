rule Win_Trojan_SillyOE_3
{
strings:
	$a0 = { fec4b92000ba3301cd217224b8023dba9e00cd218bd832e49e9f80c43eb96400ba0001cd21b4 }


condition:
	$a0
}