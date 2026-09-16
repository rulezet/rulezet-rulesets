rule TTP_XOR_MULT_DOSStub_303d {
  strings:
    $key_303d = { 64 55 [2] 10 4d [2] 57 4f [2] 10 5e [2] 5e 52 [2] 52 58 [2] 45 53 [2] 5e 1d [2] 63 }

  condition:
    any of them
}