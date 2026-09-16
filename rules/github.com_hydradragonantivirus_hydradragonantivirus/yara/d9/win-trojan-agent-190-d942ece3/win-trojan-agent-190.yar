rule Win_Trojan_Agent_190
{
strings:
	$a0 = { b800e833db8ed8c7078118813f8118740d2d00103d00b875ecb800a8ebe78ec08edbbe007c33ffb90001fcf3a5b833000650cb8edbc4064c002ea300022e8c06 }


condition:
	$a0
}