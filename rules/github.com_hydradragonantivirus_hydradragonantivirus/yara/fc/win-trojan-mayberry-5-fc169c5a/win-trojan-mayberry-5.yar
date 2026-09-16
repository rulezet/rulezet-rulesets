rule Win_Trojan_Mayberry_5
{
strings:
	$a0 = { 43cd21c3595aebeab4429933c9cd218bd0b440b90300c35b42575d004241524e4559202863 }


condition:
	$a0
}