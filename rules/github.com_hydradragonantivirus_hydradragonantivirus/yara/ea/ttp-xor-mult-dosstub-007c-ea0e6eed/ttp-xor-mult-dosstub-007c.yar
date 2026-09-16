rule TTP_XOR_MULT_DOSStub_007c {
  strings:
    $key_007c = { 54 14 [2] 20 0c [2] 67 0e [2] 20 1f [2] 6e 13 [2] 62 19 [2] 75 12 [2] 6e 5c [2] 53 }

  condition:
    any of them
}