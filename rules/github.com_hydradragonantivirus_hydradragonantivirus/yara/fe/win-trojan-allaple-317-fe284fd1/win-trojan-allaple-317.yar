rule Win_Trojan_Allaple_317
{
strings:
	$a0 = { 4b83c604 }

	$a1 = { 8bc75b5e5fc9c3 }

	$a2 = { 66c704085c00 }

	$a3 = { 8bff }

	$a4 = { 5fc9c21000 }

	$a5 = { 0bc07409 }

	$a6 = { eb00 }

	$a7 = { 8bff }

	$a8 = { 8bff }

	$a9 = { 33c0 }

	$a10 = { 83c228 }

	$a11 = { 464b }

	$a12 = { 83c228 }

	$a13 = { 8b8590fdffff5b5e5fc9c20800 }

	$a14 = { 83c604 }

	$a15 = { 33c0 }

	$a16 = { 33f6 }

	$a17 = { 8bc65b5e5fc9c21000 }

	$a18 = { 8bc65b5e5fc9c21000 }

	$a19 = { 8bfbeb06 }

	$a20 = { 80790853753c }

	$a21 = { 83f8ff7425 }

	$a22 = { 8bc35b5e5fc9c3 }

	$a23 = { c604305c }

	$a24 = { 33c0 }

	$a25 = { 313e }

	$a26 = { 0bdb75de }

	$a27 = { 4383c604 }

	$a28 = { 833e0075f7 }

	$a29 = { 83c304895dfc }

	$a30 = { 895df8 }

	$a31 = { 895df8 }

	$a32 = { e2f5 }

	$a33 = { 8bff }

	$a34 = { 83fb0775c1 }

	$a35 = { 3b5d1875b2 }

	$a36 = { 8bff }

	$a37 = { 0bc07505 }

	$a38 = { 0bc07506 }

	$a39 = { 394518740a }

	$a40 = { 8bff }

	$a41 = { 8bfbeb05 }

	$a42 = { 391675f8 }

	$a43 = { 833e0075eb }

	$a44 = { 33d2 }

	$a45 = { 33c08945fc }

	$a46 = { 8be55dc3 }

	$a47 = { 33c0 }

	$a48 = { 33c08945f8 }

	$a49 = { 558bec5133c08945fc }

	$a50 = { 595dc3 }

	$a51 = { 5dc3 }

	$a52 = { 5b5e5fc3 }

	$a53 = { 0bdb75cd }

	$a54 = { 5b5e5fc9c3 }

	$a55 = { 0bf675d7 }

	$a56 = { 8bff }

	$a57 = { 0bf675e0 }

	$a58 = { 0bc07409 }

	$a59 = { eb00 }

	$a60 = { 8bff }

	$a61 = { 8bff }

	$a62 = { eb6b }

	$a63 = { 83f8fb7505 }

	$a64 = { 83c228 }

	$a65 = { 3a04317405 }

	$a66 = { 4178f8 }

	$a67 = { 890c86 }

	$a68 = { 8b4804 }

	$a69 = { 0bc0740b }

	$a70 = { 803c385c75f9 }

	$a71 = { 33f6 }

	$a72 = { 8bff }

	$a73 = { 83f8ff750f }

	$a74 = { 8bff }

	$a75 = { 33db }

	$a76 = { 5b5e5fc9c3 }

	$a77 = { 33db }

	$a78 = { 33c0 }

	$a79 = { 313e }

	$a80 = { 3cfc7507 }

	$a81 = { 833e0075f7 }

	$a82 = { 895df8 }

	$a83 = { 895df8 }

	$a84 = { 33dbeb08 }

	$a85 = { 0bdb75ea }

	$a86 = { e2f5 }

	$a87 = { 8bff }

	$a88 = { 3b5d1875e4 }

	$a89 = { 5333dbeb3a }

	$a90 = { 5b4383c609 }

	$a91 = { 8b4610 }

	$a92 = { 83f8ff740d }

	$a93 = { 0bc07506 }

	$a94 = { 837b08007426 }

	$a95 = { 39450c7405 }

	$a96 = { 8bff }

	$a97 = { e8f87dffff }

	$a98 = { 53e8a6020000 }

	$a99 = { c745f000000000 }

	$a100 = { 8b7d14 }

	$a101 = { 33d2 }

	$a102 = { 33d2 }

	$a103 = { 33c08945f8 }

	$a104 = { 8be55dc3 }

	$a105 = { 5dc3 }

	$a106 = { 66833f007505 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52 and $a53 and $a54 and $a55 and $a56 and $a57 and $a58 and $a59 and $a60 and $a61 and $a62 and $a63 and $a64 and $a65 and $a66 and $a67 and $a68 and $a69 and $a70 and $a71 and $a72 and $a73 and $a74 and $a75 and $a76 and $a77 and $a78 and $a79 and $a80 and $a81 and $a82 and $a83 and $a84 and $a85 and $a86 and $a87 and $a88 and $a89 and $a90 and $a91 and $a92 and $a93 and $a94 and $a95 and $a96 and $a97 and $a98 and $a99 and $a100 and $a101 and $a102 and $a103 and $a104 and $a105 and $a106
}