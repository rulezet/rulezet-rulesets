rule TTP_XOR_MULT_DOSStub_068c {
  strings:
    $key_068c = { 52 e4 [2] 26 fc [2] 61 fe [2] 26 ef [2] 68 e3 [2] 64 e9 [2] 73 e2 [2] 68 ac [2] 55 }

  condition:
    any of them
}