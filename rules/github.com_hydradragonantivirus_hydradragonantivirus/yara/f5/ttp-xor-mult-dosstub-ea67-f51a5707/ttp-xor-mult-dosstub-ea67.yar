rule TTP_XOR_MULT_DOSStub_ea67 {
  strings:
    $key_ea67 = { be 0f [2] ca 17 [2] 8d 15 [2] ca 04 [2] 84 08 [2] 88 02 [2] 9f 09 [2] 84 47 [2] b9 }

  condition:
    any of them
}