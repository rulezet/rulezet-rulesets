rule TTP_XOR_MULT_DOSStub_2675 {
  strings:
    $key_2675 = { 72 1d [2] 06 05 [2] 41 07 [2] 06 16 [2] 48 1a [2] 44 10 [2] 53 1b [2] 48 55 [2] 75 }

  condition:
    any of them
}