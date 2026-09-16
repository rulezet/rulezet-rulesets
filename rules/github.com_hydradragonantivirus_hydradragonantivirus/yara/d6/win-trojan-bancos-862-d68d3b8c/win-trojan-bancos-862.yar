rule Win_Trojan_Bancos_862
{
strings:
	$a0 = { e31fe9cda96c2d3d715ebc28ad9470b1b5c96a8a9e487c55bc002f8c54dd5d41048f4ed333aa379c78a3b0dad5efc34c1ea18cd849bf318ff73c240f6d760be6c4 }


condition:
	$a0
}