rule TTP_XOR_MULT_DOSStub_345d {
  strings:
    $key_345d = { 60 35 [2] 14 2d [2] 53 2f [2] 14 3e [2] 5a 32 [2] 56 38 [2] 41 33 [2] 5a 7d [2] 67 }

  condition:
    any of them
}