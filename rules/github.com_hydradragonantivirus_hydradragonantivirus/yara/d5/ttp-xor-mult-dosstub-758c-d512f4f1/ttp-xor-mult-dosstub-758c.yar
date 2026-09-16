rule TTP_XOR_MULT_DOSStub_758c {
  strings:
    $key_758c = { 21 e4 [2] 55 fc [2] 12 fe [2] 55 ef [2] 1b e3 [2] 17 e9 [2] 00 e2 [2] 1b ac [2] 26 }

  condition:
    any of them
}