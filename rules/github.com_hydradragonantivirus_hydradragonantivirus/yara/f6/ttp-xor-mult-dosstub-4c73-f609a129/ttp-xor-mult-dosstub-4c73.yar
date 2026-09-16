rule TTP_XOR_MULT_DOSStub_4c73 {
  strings:
    $key_4c73 = { 18 1b [2] 6c 03 [2] 2b 01 [2] 6c 10 [2] 22 1c [2] 2e 16 [2] 39 1d [2] 22 53 [2] 1f }

  condition:
    any of them
}