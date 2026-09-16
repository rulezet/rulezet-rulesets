rule TTP_XOR_MULT_DOSStub_ea32 {
  strings:
    $key_ea32 = { be 5a [2] ca 42 [2] 8d 40 [2] ca 51 [2] 84 5d [2] 88 57 [2] 9f 5c [2] 84 12 [2] b9 }

  condition:
    any of them
}