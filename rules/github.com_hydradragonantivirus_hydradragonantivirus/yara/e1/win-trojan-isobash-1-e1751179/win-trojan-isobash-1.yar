rule Win_Trojan_Isobash_1
{
strings:
	$a0 = { 5c43757272656e7456657273696f6e5c52756e[0-63]2e6e7267[0-1]2e69736f[0-1]5b6175746f72756e5d[0-2]4f50454e3d }


condition:
	$a0
}