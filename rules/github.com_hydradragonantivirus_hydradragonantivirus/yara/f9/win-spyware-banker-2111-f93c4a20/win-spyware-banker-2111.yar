rule Win_Spyware_Banker_2111
{
strings:
	$a0 = { 8c102fc6e9a44ed2e07f9ba1f10d70f5aff19df9952c0b6dc09da19f64656a43ea75fc37c94a19bfebc870afa98032517c68f744f1f2f07679b730ab71d6a3fe54e57058843d3f4ab6b5f7c76487 }


condition:
	$a0
}