rule Simbin_Race_WTCC_files_encryption_version_2__8_byt_STR_16_ {
  strings:
    $a0 = "qcB81[O x_@)pobk"

  condition:
    $a0
}