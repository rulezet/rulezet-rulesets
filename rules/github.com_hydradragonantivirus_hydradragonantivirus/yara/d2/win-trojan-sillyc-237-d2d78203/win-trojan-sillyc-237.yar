rule Win_Trojan_SillyC_237
{
strings:
	$a0 = { e800005ec6440600eb06cdffb400cd168b84e000a300018a84e200a20201b41a8d94ef00cd21b44eb937008d94e600cd }


condition:
	$a0
}