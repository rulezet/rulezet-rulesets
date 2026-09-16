rule Win_Trojan_Monster_35
{
strings:
	$a0 = { 02bedc2c8034cd46e2fa25cdcd934e23ce0b89c13326cd0b89c1cd2559cc464986cf444995cf0acbcdcc00ed4749 }


condition:
	$a0
}