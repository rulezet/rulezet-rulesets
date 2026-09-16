rule Win_Trojan_Crypt_148
{
strings:
	$a0 = { 81c6????????(01|29|31)(30|31|32|33|37)81ee[0-20]3b(c6|ce|d6|de|ee|fe)0f82??ffffff }


condition:
	$a0
}