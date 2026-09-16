rule Win_Trojan_Kuarahy_1
{
strings:
	$a0 = { 2e812c8e344646e2f70f738e345b55033877dd8f5f4e2f1c054a350a308a4bad01a0619934314892e594076ec34ef38eb0 }


condition:
	$a0
}