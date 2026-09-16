rule TTP_XOR_MULT_DOSStub_4964 {
  strings:
    $key_4964 = { 1d 0c [2] 69 14 [2] 2e 16 [2] 69 07 [2] 27 0b [2] 2b 01 [2] 3c 0a [2] 27 44 [2] 1a }

  condition:
    any of them
}