rule TTP_XOR_MULT_DOSStub_687a {
  strings:
    $key_687a = { 3c 12 [2] 48 0a [2] 0f 08 [2] 48 19 [2] 06 15 [2] 0a 1f [2] 1d 14 [2] 06 5a [2] 3b }

  condition:
    any of them
}