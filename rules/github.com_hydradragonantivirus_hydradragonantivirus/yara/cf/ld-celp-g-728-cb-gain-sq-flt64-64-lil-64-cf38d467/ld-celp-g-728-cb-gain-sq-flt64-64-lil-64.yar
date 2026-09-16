rule LD_CELP_G_728_cb_gain_sq__flt64___64_lil_64_
{
strings:
	$a0 = { 893354ffff03d13f9073e9ff1f0eea3f66032d80d0f203402bb3db43cf8b1e40893354ffff03d13f9073e9ff1f0eea3f66032d80d0f203402bb3db43cf8b1e40 }

condition:
	$a0
}