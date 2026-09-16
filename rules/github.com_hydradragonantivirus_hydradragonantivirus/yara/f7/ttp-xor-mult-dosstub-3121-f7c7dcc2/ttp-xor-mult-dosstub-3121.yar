rule TTP_XOR_MULT_DOSStub_3121 {
  strings:
    $key_3121 = { 65 49 [2] 11 51 [2] 56 53 [2] 11 42 [2] 5f 4e [2] 53 44 [2] 44 4f [2] 5f 01 [2] 62 }

  condition:
    any of them
}