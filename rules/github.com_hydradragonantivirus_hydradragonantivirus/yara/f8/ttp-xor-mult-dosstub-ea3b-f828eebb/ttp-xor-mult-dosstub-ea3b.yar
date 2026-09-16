rule TTP_XOR_MULT_DOSStub_ea3b {
  strings:
    $key_ea3b = { be 53 [2] ca 4b [2] 8d 49 [2] ca 58 [2] 84 54 [2] 88 5e [2] 9f 55 [2] 84 1b [2] b9 }

  condition:
    any of them
}