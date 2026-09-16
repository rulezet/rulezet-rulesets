rule LD_CELP_G_728_cb_gain2__flt32___32_lil_32_
{
strings:
	$a0 = { 0000843f0000e73f00204a4000dcb040000084bf0000e7bf00204ac000dcb0c0 }

condition:
	$a0
}