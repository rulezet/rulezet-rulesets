rule TTP_XOR_MULT_DOSStub_ea54 {
  strings:
    $key_ea54 = { be 3c [2] ca 24 [2] 8d 26 [2] ca 37 [2] 84 3b [2] 88 31 [2] 9f 3a [2] 84 74 [2] b9 }

  condition:
    any of them
}