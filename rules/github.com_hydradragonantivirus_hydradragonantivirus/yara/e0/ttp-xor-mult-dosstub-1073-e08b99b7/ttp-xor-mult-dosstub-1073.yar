rule TTP_XOR_MULT_DOSStub_1073 {
  strings:
    $key_1073 = { 44 1b [2] 30 03 [2] 77 01 [2] 30 10 [2] 7e 1c [2] 72 16 [2] 65 1d [2] 7e 53 [2] 43 }

  condition:
    any of them
}