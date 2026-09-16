rule TTP_XOR_MULT_DOSStub_7121 {
  strings:
    $key_7121 = { 25 49 [2] 51 51 [2] 16 53 [2] 51 42 [2] 1f 4e [2] 13 44 [2] 04 4f [2] 1f 01 [2] 22 }

  condition:
    any of them
}