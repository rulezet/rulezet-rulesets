rule TTP_XOR_MULT_DOSStub_085b {
  strings:
    $key_085b = { 5c 33 [2] 28 2b [2] 6f 29 [2] 28 38 [2] 66 34 [2] 6a 3e [2] 7d 35 [2] 66 7b [2] 5b }

  condition:
    any of them
}