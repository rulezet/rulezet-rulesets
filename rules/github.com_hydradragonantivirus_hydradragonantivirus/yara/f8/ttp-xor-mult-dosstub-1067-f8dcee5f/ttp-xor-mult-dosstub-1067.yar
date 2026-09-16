rule TTP_XOR_MULT_DOSStub_1067 {
  strings:
    $key_1067 = { 44 0f [2] 30 17 [2] 77 15 [2] 30 04 [2] 7e 08 [2] 72 02 [2] 65 09 [2] 7e 47 [2] 43 }

  condition:
    any of them
}