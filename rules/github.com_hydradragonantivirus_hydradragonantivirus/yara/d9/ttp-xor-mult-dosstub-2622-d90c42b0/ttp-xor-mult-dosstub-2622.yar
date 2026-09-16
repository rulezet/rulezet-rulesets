rule TTP_XOR_MULT_DOSStub_2622 {
  strings:
    $key_2622 = { 72 4a [2] 06 52 [2] 41 50 [2] 06 41 [2] 48 4d [2] 44 47 [2] 53 4c [2] 48 02 [2] 75 }

  condition:
    any of them
}