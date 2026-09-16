rule TTP_XOR_MULT_DOSStub_375d {
  strings:
    $key_375d = { 63 35 [2] 17 2d [2] 50 2f [2] 17 3e [2] 59 32 [2] 55 38 [2] 42 33 [2] 59 7d [2] 64 }

  condition:
    any of them
}