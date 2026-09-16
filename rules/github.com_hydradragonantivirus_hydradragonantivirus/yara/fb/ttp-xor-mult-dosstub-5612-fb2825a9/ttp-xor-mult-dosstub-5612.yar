rule TTP_XOR_MULT_DOSStub_5612 {
  strings:
    $key_5612 = { 02 7a [2] 76 62 [2] 31 60 [2] 76 71 [2] 38 7d [2] 34 77 [2] 23 7c [2] 38 32 [2] 05 }

  condition:
    any of them
}