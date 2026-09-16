rule TTP_XOR_MULT_DOSStub_ea63 {
  strings:
    $key_ea63 = { be 0b [2] ca 13 [2] 8d 11 [2] ca 00 [2] 84 0c [2] 88 06 [2] 9f 0d [2] 84 43 [2] b9 }

  condition:
    any of them
}