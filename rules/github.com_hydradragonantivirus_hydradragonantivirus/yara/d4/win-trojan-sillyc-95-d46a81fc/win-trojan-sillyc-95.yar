rule Win_Trojan_SillyC_95
{
strings:
	$a0 = { e888ffb44eb927008d963101cd21730ce9dc00b44fcd217303e9d3008b8620013d0bfe77ee }


condition:
	$a0
}