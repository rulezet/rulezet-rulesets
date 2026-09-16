rule TTP_XOR_MULT_DOSStub_ea31 {
  strings:
    $key_ea31 = { be 59 [2] ca 41 [2] 8d 43 [2] ca 52 [2] 84 5e [2] 88 54 [2] 9f 5f [2] 84 11 [2] b9 }

  condition:
    any of them
}