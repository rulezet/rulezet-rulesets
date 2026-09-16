rule TTP_XOR_MULT_DOSStub_125c {
  strings:
    $key_125c = { 46 34 [2] 32 2c [2] 75 2e [2] 32 3f [2] 7c 33 [2] 70 39 [2] 67 32 [2] 7c 7c [2] 41 }

  condition:
    any of them
}