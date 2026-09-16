rule TTP_XOR_MULT_DOSStub_e26d {
  strings:
    $key_e26d = { b6 05 [2] c2 1d [2] 85 1f [2] c2 0e [2] 8c 02 [2] 80 08 [2] 97 03 [2] 8c 4d [2] b1 }

  condition:
    any of them
}