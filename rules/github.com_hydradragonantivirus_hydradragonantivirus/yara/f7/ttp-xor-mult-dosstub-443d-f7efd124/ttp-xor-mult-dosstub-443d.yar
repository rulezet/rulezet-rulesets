rule TTP_XOR_MULT_DOSStub_443d {
  strings:
    $key_443d = { 10 55 [2] 64 4d [2] 23 4f [2] 64 5e [2] 2a 52 [2] 26 58 [2] 31 53 [2] 2a 1d [2] 17 }

  condition:
    any of them
}