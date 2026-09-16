rule TTP_XOR_MULT_DOSStub_6020 {
  strings:
    $key_6020 = { 34 48 [2] 40 50 [2] 07 52 [2] 40 43 [2] 0e 4f [2] 02 45 [2] 15 4e [2] 0e 00 [2] 33 }

  condition:
    any of them
}