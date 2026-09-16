rule Win_Trojan_Mybot_5994
{
strings:
	$a0 = { ea10014baff28a5dea4dc7d9fee5999cb3ae785e74f99cbf74b9ccfb97cce533ee5ff7dd33c0f3c3739ba6746785ba3c126739d274bd33dffce478788a7a514560ed329dae19aad1e76c7a860859e10586ae }


condition:
	$a0
}