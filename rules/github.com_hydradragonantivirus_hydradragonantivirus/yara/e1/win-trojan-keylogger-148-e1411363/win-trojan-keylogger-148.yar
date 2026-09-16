rule Win_Trojan_Keylogger_148
{
strings:
	$a0 = { 65796c6f67676572266c673d9383e01efb463dd369643d5c5200f6bad6bd6b2707762a166b2e06 }


condition:
	$a0
}