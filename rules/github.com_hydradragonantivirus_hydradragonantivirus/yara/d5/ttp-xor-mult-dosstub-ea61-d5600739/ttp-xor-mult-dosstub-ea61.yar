rule TTP_XOR_MULT_DOSStub_ea61 {
  strings:
    $key_ea61 = { be 09 [2] ca 11 [2] 8d 13 [2] ca 02 [2] 84 0e [2] 88 04 [2] 9f 0f [2] 84 41 [2] b9 }

  condition:
    any of them
}