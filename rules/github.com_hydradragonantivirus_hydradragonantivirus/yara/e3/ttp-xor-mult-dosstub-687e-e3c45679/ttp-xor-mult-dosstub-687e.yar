rule TTP_XOR_MULT_DOSStub_687e {
  strings:
    $key_687e = { 3c 16 [2] 48 0e [2] 0f 0c [2] 48 1d [2] 06 11 [2] 0a 1b [2] 1d 10 [2] 06 5e [2] 3b }

  condition:
    any of them
}