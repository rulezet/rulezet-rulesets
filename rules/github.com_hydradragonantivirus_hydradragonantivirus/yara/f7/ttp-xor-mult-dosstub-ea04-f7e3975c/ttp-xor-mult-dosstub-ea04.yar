rule TTP_XOR_MULT_DOSStub_ea04 {
  strings:
    $key_ea04 = { be 6c [2] ca 74 [2] 8d 76 [2] ca 67 [2] 84 6b [2] 88 61 [2] 9f 6a [2] 84 24 [2] b9 }

  condition:
    any of them
}