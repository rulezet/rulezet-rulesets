rule TTP_XOR_MULT_DOSStub_a38c {
  strings:
    $key_a38c = { f7 e4 [2] 83 fc [2] c4 fe [2] 83 ef [2] cd e3 [2] c1 e9 [2] d6 e2 [2] cd ac [2] f0 }

  condition:
    any of them
}