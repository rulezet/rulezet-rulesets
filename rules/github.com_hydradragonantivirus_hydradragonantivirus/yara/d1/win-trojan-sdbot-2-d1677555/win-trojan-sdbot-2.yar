rule Win_Trojan_SDBot_2
{
strings:
	$a0 = { 782e6f7267b5236a65616e50006bfea119d9657905eb66696c652e6578fff7dfcd2f439f1d67757261746913204c6f61 }


condition:
	$a0
}