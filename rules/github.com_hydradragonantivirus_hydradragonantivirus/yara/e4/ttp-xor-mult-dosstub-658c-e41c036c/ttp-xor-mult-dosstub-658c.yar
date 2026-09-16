rule TTP_XOR_MULT_DOSStub_658c {
  strings:
    $key_658c = { 31 e4 [2] 45 fc [2] 02 fe [2] 45 ef [2] 0b e3 [2] 07 e9 [2] 10 e2 [2] 0b ac [2] 36 }

  condition:
    any of them
}