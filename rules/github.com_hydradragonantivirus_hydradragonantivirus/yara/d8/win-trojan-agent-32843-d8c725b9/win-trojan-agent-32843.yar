rule Win_Trojan_Agent_32843
{
strings:
	$a0 = { 3a2477fbbc9748597db480178ecea06e9f46d03a43cdfbf7386d513a1d85a95dd65bfba0f0016ce19538e5b4e1cc0a9699900fc85e395d69623a9b9a9fafccc5ad }


condition:
	$a0
}