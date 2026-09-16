rule TTP_XOR_MULT_DOSStub_e58c {
  strings:
    $key_e58c = { b1 e4 [2] c5 fc [2] 82 fe [2] c5 ef [2] 8b e3 [2] 87 e9 [2] 90 e2 [2] 8b ac [2] b6 }

  condition:
    any of them
}