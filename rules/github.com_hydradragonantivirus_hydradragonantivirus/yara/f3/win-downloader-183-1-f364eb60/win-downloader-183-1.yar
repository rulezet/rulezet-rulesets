rule Win_Downloader_183_1
{
strings:
	$a0 = { cdeac68567fcffff6a80e5f9c68563fcffff6c80c2e980e994c68559fcffff61c6855efcffff7280c5b980e63ac68561fcffff6e80c1c080e50ac68564fcffff65b68dc68558fcffff57b22980f593c6855ffcffff }


condition:
	$a0
}