rule Win_Trojan_Mini_25
{
strings:
	$a0 = { 8cd80500108ec0be00018bfeb18bf3a48ed81eb8180150cb33d2b41acd21ba5401b53fb44ecd21724bba1e00b8023dcd21721b8bd8bf1a008b0d8bd6b43fcd21 }


condition:
	$a0
}