rule TTP_XOR_MULT_DOSStub_ea10 {
  strings:
    $key_ea10 = { be 78 [2] ca 60 [2] 8d 62 [2] ca 73 [2] 84 7f [2] 88 75 [2] 9f 7e [2] 84 30 [2] b9 }

  condition:
    any of them
}