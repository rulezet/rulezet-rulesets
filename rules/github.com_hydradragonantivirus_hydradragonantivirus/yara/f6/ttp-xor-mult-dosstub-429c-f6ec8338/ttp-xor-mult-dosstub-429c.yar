rule TTP_XOR_MULT_DOSStub_429c {
  strings:
    $key_429c = { 16 f4 [2] 62 ec [2] 25 ee [2] 62 ff [2] 2c f3 [2] 20 f9 [2] 37 f2 [2] 2c bc [2] 11 }

  condition:
    any of them
}