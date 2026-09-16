rule TTP_XOR_MULT_DOSStub_4061 {
  strings:
    $key_4061 = { 14 09 [2] 60 11 [2] 27 13 [2] 60 02 [2] 2e 0e [2] 22 04 [2] 35 0f [2] 2e 41 [2] 13 }

  condition:
    any of them
}