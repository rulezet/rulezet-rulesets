rule TTP_XOR_MULT_DOSStub_d08c {
  strings:
    $key_d08c = { 84 e4 [2] f0 fc [2] b7 fe [2] f0 ef [2] be e3 [2] b2 e9 [2] a5 e2 [2] be ac [2] 83 }

  condition:
    any of them
}