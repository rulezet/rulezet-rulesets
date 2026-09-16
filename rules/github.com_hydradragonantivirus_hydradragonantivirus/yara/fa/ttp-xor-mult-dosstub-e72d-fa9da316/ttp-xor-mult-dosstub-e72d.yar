rule TTP_XOR_MULT_DOSStub_e72d {
  strings:
    $key_e72d = { b3 45 [2] c7 5d [2] 80 5f [2] c7 4e [2] 89 42 [2] 85 48 [2] 92 43 [2] 89 0d [2] b4 }

  condition:
    any of them
}