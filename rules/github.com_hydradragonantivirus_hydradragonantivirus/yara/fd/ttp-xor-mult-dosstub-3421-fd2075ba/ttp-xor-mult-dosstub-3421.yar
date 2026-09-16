rule TTP_XOR_MULT_DOSStub_3421 {
  strings:
    $key_3421 = { 60 49 [2] 14 51 [2] 53 53 [2] 14 42 [2] 5a 4e [2] 56 44 [2] 41 4f [2] 5a 01 [2] 67 }

  condition:
    any of them
}