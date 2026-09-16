rule TTP_XOR_MULT_DOSStub_3c74 {
  strings:
    $key_3c74 = { 68 1c [2] 1c 04 [2] 5b 06 [2] 1c 17 [2] 52 1b [2] 5e 11 [2] 49 1a [2] 52 54 [2] 6f }

  condition:
    any of them
}