rule Win_Adware_Lop_198
{
strings:
	$a0 = { a306c3e385d265780c4bc0c6443e6d8db699b03d658eac250f0f89df077e5093b6f4c043e056bf66a0866ad2bfdc2a26a60448970c08d639bf021619 }


condition:
	$a0
}