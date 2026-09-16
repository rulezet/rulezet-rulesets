rule SUSP_Reverse_Run_Key {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects a Reversed Run Key"

	strings:
		$run = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide

	condition:
		 filesize < 100KB and $run
}