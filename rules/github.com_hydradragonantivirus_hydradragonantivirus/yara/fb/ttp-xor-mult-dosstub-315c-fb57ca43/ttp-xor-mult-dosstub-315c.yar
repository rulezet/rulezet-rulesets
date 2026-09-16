rule TTP_XOR_MULT_DOSStub_315c {
  strings:
    $key_315c = { 65 34 [2] 11 2c [2] 56 2e [2] 11 3f [2] 5f 33 [2] 53 39 [2] 44 32 [2] 5f 7c [2] 62 }

  condition:
    any of them
}