rule anti_debug__SEH_handler_trick__alternate_way___8_byt_24_
{
strings:
	$a0 = { 894424fc268b9900010000538b04248b1826898100010000 }

condition:
	$a0
}