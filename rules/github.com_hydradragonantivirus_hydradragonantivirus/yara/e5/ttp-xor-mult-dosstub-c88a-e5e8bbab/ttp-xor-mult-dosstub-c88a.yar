rule TTP_XOR_MULT_DOSStub_c88a {
  strings:
    $key_c88a = { 9c e2 [2] e8 fa [2] af f8 [2] e8 e9 [2] a6 e5 [2] aa ef [2] bd e4 [2] a6 aa [2] 9b }

  condition:
    any of them
}