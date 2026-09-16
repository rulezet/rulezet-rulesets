rule Win_Trojan_GhostVoice_2
{
strings:
	$a0 = { c3558bec83ec5853568bf18d45fc508d8684160050fd6dfbef1c381233db395dfc750723e90d014266399eecefdcffdd73578dbe06751253538d8e902b2a3f34 }


condition:
	$a0
}