rule Win_Trojan_Tu_1
{
strings:
	$a0 = { 095b81ebc40931c048cd21487403e81900fcbe9f0001debf000157a5a5bf0010a531c031db31ff31f6 }


condition:
	$a0
}