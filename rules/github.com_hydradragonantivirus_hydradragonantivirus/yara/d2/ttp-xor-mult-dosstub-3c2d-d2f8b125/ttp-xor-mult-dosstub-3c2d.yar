rule TTP_XOR_MULT_DOSStub_3c2d {
  strings:
    $key_3c2d = { 68 45 [2] 1c 5d [2] 5b 5f [2] 1c 4e [2] 52 42 [2] 5e 48 [2] 49 43 [2] 52 0d [2] 6f }

  condition:
    any of them
}