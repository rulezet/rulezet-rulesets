rule TTP_XOR_MULT_DOSStub_7ce3 {
  strings:
    $key_7ce3 = { 28 8b [2] 5c 93 [2] 1b 91 [2] 5c 80 [2] 12 8c [2] 1e 86 [2] 09 8d [2] 12 c3 [2] 2f }

  condition:
    any of them
}