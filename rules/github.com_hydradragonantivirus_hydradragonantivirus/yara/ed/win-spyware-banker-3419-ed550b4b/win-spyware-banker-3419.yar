rule Win_Spyware_Banker_3419
{
strings:
	$a0 = { cb0b4839d8d13acdabc7c9adde22d6e7d0ee9e9e8276044e5236c2d3d344a16850b555167bd1f244e23539d8873b3bfce7b1708edd465d13c953585c3dcb2939681ad8b25c832c9a5e055b }


condition:
	$a0
}