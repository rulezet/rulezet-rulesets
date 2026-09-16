rule Win_Trojan_Jerusalem_43
{
strings:
	$a0 = { c08ec0bffc02fcb90200f3aff9740db80421cd2000f970bff97501f807c3bb8c00b44acd21c31e31c08ed8faa124 }


condition:
	$a0
}