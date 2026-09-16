import "pe"
rule SFX_CAB : Microsoft
{
	meta:
		author="_pusher_"
		date = "2016-07"
								condition:
		    for any i in (0..pe.number_of_resources - 1):
 		     ((pe.resources[i].name_string == "C\x00A\x00B\x00I\x00N\x00E\x00T\x00" or "CABINET") and uint32be(pe.resources[i].offset) == 0x4D534346)
}