rule Win_Dropper_Agent_33399
{
strings:
	$a0 = { 33c0f2aef7d12bf98bf78bc18bfac1e902f3a58bc883e103f3a48d8de8feffff516804010000ff1524304000bf405040008d95e8feffff83c9ff33c0f2aef7d12bf98bf78bd98bfa83c9ff33c0f2ae83c7 }


condition:
	$a0
}