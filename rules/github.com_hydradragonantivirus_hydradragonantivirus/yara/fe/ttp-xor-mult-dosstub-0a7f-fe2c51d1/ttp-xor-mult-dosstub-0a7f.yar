rule TTP_XOR_MULT_DOSStub_0a7f {
  strings:
    $key_0a7f = { 5e 17 [2] 2a 0f [2] 6d 0d [2] 2a 1c [2] 64 10 [2] 68 1a [2] 7f 11 [2] 64 5f [2] 59 }

  condition:
    any of them
}