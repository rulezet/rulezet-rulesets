rule Win_Trojan_Nostardamus_8
{
strings:
	$a0 = { 7878220c48cc30c38787b559f9836a790a7ccc30b5590ae330f6b8825ebf7e797878785ef8467878 }


condition:
	$a0
}