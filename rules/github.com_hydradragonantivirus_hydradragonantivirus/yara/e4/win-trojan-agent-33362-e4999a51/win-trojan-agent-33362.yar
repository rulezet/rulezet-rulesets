rule Win_Trojan_Agent_33362
{
strings:
	$a0 = { da34336d31f1dcca11bda6cb5b50674fdb19cb64b5e9d9f5c4ba4da8b1d43a0a8c8655cd97eda558a5a2502367cde1a97ed3d8626caf40eafe7e9924a6da57bb287d4c53e3b00970778b408df5cb }


condition:
	$a0
}