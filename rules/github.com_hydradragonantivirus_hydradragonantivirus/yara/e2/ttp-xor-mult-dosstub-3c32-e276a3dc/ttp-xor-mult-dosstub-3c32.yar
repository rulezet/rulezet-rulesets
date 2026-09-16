rule TTP_XOR_MULT_DOSStub_3c32 {
  strings:
    $key_3c32 = { 68 5a [2] 1c 42 [2] 5b 40 [2] 1c 51 [2] 52 5d [2] 5e 57 [2] 49 5c [2] 52 12 [2] 6f }

  condition:
    any of them
}