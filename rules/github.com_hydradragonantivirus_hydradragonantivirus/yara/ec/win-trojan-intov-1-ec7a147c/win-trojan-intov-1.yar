rule Win_Trojan_IntOv_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd211f5633c033db33c933d233ed33f633ff1e07 }


condition:
	$a0
}