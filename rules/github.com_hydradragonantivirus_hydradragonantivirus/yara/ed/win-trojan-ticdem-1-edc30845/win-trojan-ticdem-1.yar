rule Win_Trojan_TicDem_1
{
strings:
	$a0 = { 0100568cc880c4108ec033ffb90068f3a4bafe00b41acd21ba0162b44eeb06b43ecd21b44f0e1fcd21b9fe1e720404 }


condition:
	$a0
}