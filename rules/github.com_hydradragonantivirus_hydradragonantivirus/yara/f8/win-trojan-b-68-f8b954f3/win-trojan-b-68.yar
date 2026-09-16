rule Win_Trojan_B_68
{
strings:
	$a0 = { 33c08ed8a113042d0500a31304b106d3e08ed88ec02e8b162a0e33db2e8b0e280eb80802e86eff }


condition:
	$a0
}