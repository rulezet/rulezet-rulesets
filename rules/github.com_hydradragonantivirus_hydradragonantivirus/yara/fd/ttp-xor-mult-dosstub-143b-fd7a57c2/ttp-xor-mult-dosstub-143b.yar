rule TTP_XOR_MULT_DOSStub_143b {
  strings:
    $key_143b = { 40 53 [2] 34 4b [2] 73 49 [2] 34 58 [2] 7a 54 [2] 76 5e [2] 61 55 [2] 7a 1b [2] 47 }

  condition:
    any of them
}