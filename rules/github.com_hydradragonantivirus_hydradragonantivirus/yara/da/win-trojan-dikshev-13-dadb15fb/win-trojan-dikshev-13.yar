rule Win_Trojan_Dikshev_13
{
strings:
	$a0 = { 2a434f4d56918bd6adadb44ecd21720dba9e00b82e5bae75fda5a4cd215a720793b12bb440cd }


condition:
	$a0
}