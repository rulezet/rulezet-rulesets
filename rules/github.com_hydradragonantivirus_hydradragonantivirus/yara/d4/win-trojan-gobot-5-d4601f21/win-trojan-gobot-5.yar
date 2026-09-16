rule Win_Trojan_Gobot_5
{
strings:
	$a0 = { 2009575affd2b802faba455932dbcd16b82435cd218c063509891e3709b82425bad802cd211e07fe062a07b44e33c9 }


condition:
	$a0
}