rule TTP_XOR_MULT_DOSStub_6331 {
  strings:
    $key_6331 = { 37 59 [2] 43 41 [2] 04 43 [2] 43 52 [2] 0d 5e [2] 01 54 [2] 16 5f [2] 0d 11 [2] 30 }

  condition:
    any of them
}