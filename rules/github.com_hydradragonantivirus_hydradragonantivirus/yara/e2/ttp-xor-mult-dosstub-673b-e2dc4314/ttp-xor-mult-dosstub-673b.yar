rule TTP_XOR_MULT_DOSStub_673b {
  strings:
    $key_673b = { 33 53 [2] 47 4b [2] 00 49 [2] 47 58 [2] 09 54 [2] 05 5e [2] 12 55 [2] 09 1b [2] 34 }

  condition:
    any of them
}