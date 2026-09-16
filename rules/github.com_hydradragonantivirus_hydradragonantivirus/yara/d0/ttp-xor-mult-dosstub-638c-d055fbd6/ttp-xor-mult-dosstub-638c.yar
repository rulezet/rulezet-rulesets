rule TTP_XOR_MULT_DOSStub_638c {
  strings:
    $key_638c = { 37 e4 [2] 43 fc [2] 04 fe [2] 43 ef [2] 0d e3 [2] 01 e9 [2] 16 e2 [2] 0d ac [2] 30 }

  condition:
    any of them
}