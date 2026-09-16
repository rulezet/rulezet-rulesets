rule BHEncodeTable__8_byt_ASC_64_ {
  strings:
    $a0 = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr"

  condition:
    $a0
}