rule TTP_XOR_MULT_DOSStub_ea11 {
  strings:
    $key_ea11 = { be 79 [2] ca 61 [2] 8d 63 [2] ca 72 [2] 84 7e [2] 88 74 [2] 9f 7f [2] 84 31 [2] b9 }

  condition:
    any of them
}