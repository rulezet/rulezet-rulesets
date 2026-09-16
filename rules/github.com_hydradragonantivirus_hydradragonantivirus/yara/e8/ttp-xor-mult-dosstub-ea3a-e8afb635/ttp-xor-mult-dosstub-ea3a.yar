rule TTP_XOR_MULT_DOSStub_ea3a {
  strings:
    $key_ea3a = { be 52 [2] ca 4a [2] 8d 48 [2] ca 59 [2] 84 55 [2] 88 5f [2] 9f 54 [2] 84 1a [2] b9 }

  condition:
    any of them
}