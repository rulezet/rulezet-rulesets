rule Win_Trojan_Animality_1
{
strings:
	$a0 = { 49e84e0790909c2e803e06050174062eff1e3800cf9d2e8c16eb052e8926ed052e8c0eef05bc8e06902e8e16ef052e }


condition:
	$a0
}