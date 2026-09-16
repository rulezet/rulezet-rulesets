rule TTP_XOR_MULT_DOSStub_210c {
  strings:
    $key_210c = { 75 64 [2] 01 7c [2] 46 7e [2] 01 6f [2] 4f 63 [2] 43 69 [2] 54 62 [2] 4f 2c [2] 72 }

  condition:
    any of them
}