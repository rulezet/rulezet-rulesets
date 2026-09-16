rule TTP_XOR_MULT_DOSStub_653b {
  strings:
    $key_653b = { 31 53 [2] 45 4b [2] 02 49 [2] 45 58 [2] 0b 54 [2] 07 5e [2] 10 55 [2] 0b 1b [2] 36 }

  condition:
    any of them
}