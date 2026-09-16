rule Win_Spyware_Banker_3065
{
strings:
	$a0 = { 83d50fcc21b32918376f09e9a1cf16102875770fcb70961ba5c9b923096364b5cab4b03311d28f8359d684c31fa798ca32c8 }


condition:
	$a0
}