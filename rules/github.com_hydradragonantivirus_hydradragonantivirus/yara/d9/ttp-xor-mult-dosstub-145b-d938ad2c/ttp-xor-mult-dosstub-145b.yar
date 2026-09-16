rule TTP_XOR_MULT_DOSStub_145b {
  strings:
    $key_145b = { 40 33 [2] 34 2b [2] 73 29 [2] 34 38 [2] 7a 34 [2] 76 3e [2] 61 35 [2] 7a 7b [2] 47 }

  condition:
    any of them
}