rule TTP_XOR_MULT_DOSStub_ea0a {
  strings:
    $key_ea0a = { be 62 [2] ca 7a [2] 8d 78 [2] ca 69 [2] 84 65 [2] 88 6f [2] 9f 64 [2] 84 2a [2] b9 }

  condition:
    any of them
}