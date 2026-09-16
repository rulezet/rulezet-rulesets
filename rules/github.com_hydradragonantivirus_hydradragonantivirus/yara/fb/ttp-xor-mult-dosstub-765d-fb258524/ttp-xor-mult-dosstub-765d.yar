rule TTP_XOR_MULT_DOSStub_765d {
  strings:
    $key_765d = { 22 35 [2] 56 2d [2] 11 2f [2] 56 3e [2] 18 32 [2] 14 38 [2] 03 33 [2] 18 7d [2] 25 }

  condition:
    any of them
}