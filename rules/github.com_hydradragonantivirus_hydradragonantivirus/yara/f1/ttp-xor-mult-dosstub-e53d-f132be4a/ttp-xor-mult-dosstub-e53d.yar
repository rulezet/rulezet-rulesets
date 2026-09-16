rule TTP_XOR_MULT_DOSStub_e53d {
  strings:
    $key_e53d = { b1 55 [2] c5 4d [2] 82 4f [2] c5 5e [2] 8b 52 [2] 87 58 [2] 90 53 [2] 8b 1d [2] b6 }

  condition:
    any of them
}