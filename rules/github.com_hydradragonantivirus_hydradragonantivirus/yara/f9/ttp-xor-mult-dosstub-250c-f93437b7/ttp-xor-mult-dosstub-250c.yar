rule TTP_XOR_MULT_DOSStub_250c {
  strings:
    $key_250c = { 71 64 [2] 05 7c [2] 42 7e [2] 05 6f [2] 4b 63 [2] 47 69 [2] 50 62 [2] 4b 2c [2] 76 }

  condition:
    any of them
}