rule TTP_XOR_MULT_DOSStub_2a11 {
  strings:
    $key_2a11 = { 7e 79 [2] 0a 61 [2] 4d 63 [2] 0a 72 [2] 44 7e [2] 48 74 [2] 5f 7f [2] 44 31 [2] 79 }

  condition:
    any of them
}