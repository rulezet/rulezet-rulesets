rule AAC_pred_max_bands_tbl__avcodec___8_byt_16_ {
  strings:
    $a0 = { 21 21 26 28 28 28 29 29 25 25 25 22 00 00 00 00 }

  condition:
    $a0
}