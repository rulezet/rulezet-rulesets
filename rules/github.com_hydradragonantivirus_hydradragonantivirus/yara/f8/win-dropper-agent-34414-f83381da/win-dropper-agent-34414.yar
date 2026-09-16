rule Win_Dropper_Agent_34414
{
strings:
	$a0 = { 5351bb59190000baa42940008a0ac0c107c0c90228d180f191880a4a4b75ed595b81c2c51c0000ffe2000000 }


condition:
	$a0
}