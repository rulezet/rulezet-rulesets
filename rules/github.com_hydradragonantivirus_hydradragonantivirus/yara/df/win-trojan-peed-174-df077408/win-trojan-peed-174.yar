rule Win_Trojan_Peed_174
{
strings:
	$a0 = { 69c0cc5a0000e986000000f7db29dff7db01de89c3e9a5000000ba0400000087d181c48304000081ec7f0400006a42ff }


condition:
	$a0
}