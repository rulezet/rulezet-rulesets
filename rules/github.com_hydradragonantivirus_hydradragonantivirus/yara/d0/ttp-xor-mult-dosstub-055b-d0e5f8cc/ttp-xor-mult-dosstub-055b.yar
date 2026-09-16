rule TTP_XOR_MULT_DOSStub_055b {
  strings:
    $key_055b = { 51 33 [2] 25 2b [2] 62 29 [2] 25 38 [2] 6b 34 [2] 67 3e [2] 70 35 [2] 6b 7b [2] 56 }

  condition:
    any of them
}