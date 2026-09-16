rule Win_Trojan_Y3KRat_2
{
strings:
	$a0 = { c6bfb21dd71142bdc489241e61125c707a93ccb1ff121bec663ad571ec322b62142f4718a6db79d43b4e8c3f8ac5044f4aca831316db8e2f45974b905533412c }


condition:
	$a0
}