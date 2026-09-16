rule TTP_XOR_MULT_DOSStub_358c {
  strings:
    $key_358c = { 61 e4 [2] 15 fc [2] 52 fe [2] 15 ef [2] 5b e3 [2] 57 e9 [2] 40 e2 [2] 5b ac [2] 66 }

  condition:
    any of them
}