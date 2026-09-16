rule Win_Trojan_Rukap_62
{
strings:
	$a0 = { 5d615a877c6d627141b0a0ca550df989ff4ef7cd892bbef3e150af9fc5cb8011241ecc8589cf7ccc1c4e0b2789c391d97043a0f2864e8551ef12f50f53fd03343d59e2b991edaadf }


condition:
	$a0
}