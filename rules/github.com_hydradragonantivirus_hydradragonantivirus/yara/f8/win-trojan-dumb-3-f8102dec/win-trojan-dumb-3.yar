rule Win_Trojan_Dumb_3
{
strings:
	$a0 = { bf00015781ed07018db6d901a5a48d96df01e8ddffb44e8d96d30133c9888e090280be09020377c7cd2172c3b8023d }


condition:
	$a0
}