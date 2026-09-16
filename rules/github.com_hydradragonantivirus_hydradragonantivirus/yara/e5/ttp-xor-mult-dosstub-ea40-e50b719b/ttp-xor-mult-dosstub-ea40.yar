rule TTP_XOR_MULT_DOSStub_ea40 {
  strings:
    $key_ea40 = { be 28 [2] ca 30 [2] 8d 32 [2] ca 23 [2] 84 2f [2] 88 25 [2] 9f 2e [2] 84 60 [2] b9 }

  condition:
    any of them
}