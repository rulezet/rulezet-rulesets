rule TTP_XOR_MULT_DOSStub_eaf5 {
  strings:
    $key_eaf5 = { be 9d [2] ca 85 [2] 8d 87 [2] ca 96 [2] 84 9a [2] 88 90 [2] 9f 9b [2] 84 d5 [2] b9 }

  condition:
    any of them
}