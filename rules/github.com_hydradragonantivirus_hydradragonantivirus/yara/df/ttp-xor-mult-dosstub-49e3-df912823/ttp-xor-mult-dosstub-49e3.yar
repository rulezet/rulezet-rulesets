rule TTP_XOR_MULT_DOSStub_49e3 {
  strings:
    $key_49e3 = { 1d 8b [2] 69 93 [2] 2e 91 [2] 69 80 [2] 27 8c [2] 2b 86 [2] 3c 8d [2] 27 c3 [2] 1a }

  condition:
    any of them
}