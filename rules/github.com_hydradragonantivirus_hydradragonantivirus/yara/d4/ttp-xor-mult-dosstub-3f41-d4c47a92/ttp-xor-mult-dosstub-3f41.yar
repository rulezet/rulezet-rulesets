rule TTP_XOR_MULT_DOSStub_3f41 {
  strings:
    $key_3f41 = { 6b 29 [2] 1f 31 [2] 58 33 [2] 1f 22 [2] 51 2e [2] 5d 24 [2] 4a 2f [2] 51 61 [2] 6c }

  condition:
    any of them
}