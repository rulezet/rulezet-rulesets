rule Win_Trojan_C_48
{
strings:
	$a0 = { 1abadb03cd21b42acd2183fa657507b409ba7b02cd21b447b200be2102cd21b44eb90000ba6402 }


condition:
	$a0
}