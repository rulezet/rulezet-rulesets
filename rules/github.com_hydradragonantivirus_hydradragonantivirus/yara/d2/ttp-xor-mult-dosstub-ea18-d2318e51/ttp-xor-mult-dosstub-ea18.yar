rule TTP_XOR_MULT_DOSStub_ea18 {
  strings:
    $key_ea18 = { be 70 [2] ca 68 [2] 8d 6a [2] ca 7b [2] 84 77 [2] 88 7d [2] 9f 76 [2] 84 38 [2] b9 }

  condition:
    any of them
}