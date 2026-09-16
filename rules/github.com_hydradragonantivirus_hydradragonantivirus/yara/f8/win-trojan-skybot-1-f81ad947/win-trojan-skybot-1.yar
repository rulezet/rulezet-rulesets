rule Win_Trojan_Skybot_1
{
strings:
	$a0 = { 4d6963726f736f66745c57696e646f7773204e545c43757272656e7456657273696f6e }

	$a1 = { 2e6b696c6c70726f63 }


condition:
	$a0 and $a1
}