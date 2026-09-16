rule TTP_XOR_MULT_DOSStub_ea7a {
  strings:
    $key_ea7a = { be 12 [2] ca 0a [2] 8d 08 [2] ca 19 [2] 84 15 [2] 88 1f [2] 9f 14 [2] 84 5a [2] b9 }

  condition:
    any of them
}