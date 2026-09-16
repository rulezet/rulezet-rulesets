rule TTP_XOR_MULT_DOSStub_553b {
  strings:
    $key_553b = { 01 53 [2] 75 4b [2] 32 49 [2] 75 58 [2] 3b 54 [2] 37 5e [2] 20 55 [2] 3b 1b [2] 06 }

  condition:
    any of them
}