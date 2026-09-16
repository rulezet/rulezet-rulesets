rule Win_Dropper_Agent_35872
{
strings:
	$a0 = { e84f7a0000e916feffff6a0c6838af4d00e88f3a00008365e4008b75083b35cce84d0077226a04e8483c }


condition:
	$a0
}