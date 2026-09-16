rule Win_Trojan_SuperWorm_1
{
strings:
	$a0 = { 0b00e82300b000b44ccd210000e80301bb5302e8be00e89c008bebbf7202e84a00e82600e82f00 }


condition:
	$a0
}