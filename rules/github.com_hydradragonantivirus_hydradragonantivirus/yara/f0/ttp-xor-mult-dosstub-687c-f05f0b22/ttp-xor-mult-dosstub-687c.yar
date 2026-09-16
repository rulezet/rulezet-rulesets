rule TTP_XOR_MULT_DOSStub_687c {
  strings:
    $key_687c = { 3c 14 [2] 48 0c [2] 0f 0e [2] 48 1f [2] 06 13 [2] 0a 19 [2] 1d 12 [2] 06 5c [2] 3b }

  condition:
    any of them
}