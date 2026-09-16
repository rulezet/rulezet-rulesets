rule TTP_XOR_MULT_DOSStub_3761 {
  strings:
    $key_3761 = { 63 09 [2] 17 11 [2] 50 13 [2] 17 02 [2] 59 0e [2] 55 04 [2] 42 0f [2] 59 41 [2] 64 }

  condition:
    any of them
}