rule TTP_XOR_MULT_DOSStub_2632 {
  strings:
    $key_2632 = { 72 5a [2] 06 42 [2] 41 40 [2] 06 51 [2] 48 5d [2] 44 57 [2] 53 5c [2] 48 12 [2] 75 }

  condition:
    any of them
}