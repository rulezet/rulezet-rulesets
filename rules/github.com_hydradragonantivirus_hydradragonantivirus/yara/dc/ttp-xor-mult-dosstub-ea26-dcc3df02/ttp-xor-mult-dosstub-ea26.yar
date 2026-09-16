rule TTP_XOR_MULT_DOSStub_ea26 {
  strings:
    $key_ea26 = { be 4e [2] ca 56 [2] 8d 54 [2] ca 45 [2] 84 49 [2] 88 43 [2] 9f 48 [2] 84 06 [2] b9 }

  condition:
    any of them
}