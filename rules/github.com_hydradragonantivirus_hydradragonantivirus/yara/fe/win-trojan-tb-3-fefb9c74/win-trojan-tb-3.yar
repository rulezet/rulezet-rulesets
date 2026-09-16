rule Win_Trojan_TB_3
{
strings:
	$a0 = { 96cdeccccd3b064801cdec26cdec28cd8175f9cdec1abe4001cd96cdb8cdb2be3c01cd96cdb8cd }


condition:
	$a0
}