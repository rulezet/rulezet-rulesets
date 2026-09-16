rule TTP_XOR_MULT_DOSStub_f073 {
  strings:
    $key_f073 = { a4 1b [2] d0 03 [2] 97 01 [2] d0 10 [2] 9e 1c [2] 92 16 [2] 85 1d [2] 9e 53 [2] a3 }

  condition:
    any of them
}