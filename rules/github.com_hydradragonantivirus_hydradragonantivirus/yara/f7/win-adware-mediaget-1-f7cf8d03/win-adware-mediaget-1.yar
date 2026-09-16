rule Win_Adware_MediaGet_1
{
strings:
	$a0 = { 4d65646961676574446f776e6c6f61646572496e666f3d282e2a3f293b2e2a }


condition:
	$a0
}