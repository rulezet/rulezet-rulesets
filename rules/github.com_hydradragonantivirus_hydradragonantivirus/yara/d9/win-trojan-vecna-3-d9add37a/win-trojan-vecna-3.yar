rule Win_Trojan_Vecna_3
{
strings:
	$a0 = { 5e2bff803dcd753bb8ffffcd133cfe7420b80102e86c00803fe87415b801035041e8660058 }


condition:
	$a0
}