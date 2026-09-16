rule TTP_XOR_MULT_DOSStub_3c59 {
  strings:
    $key_3c59 = { 68 31 [2] 1c 29 [2] 5b 2b [2] 1c 3a [2] 52 36 [2] 5e 3c [2] 49 37 [2] 52 79 [2] 6f }

  condition:
    any of them
}