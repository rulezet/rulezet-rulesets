rule TTP_XOR_MULT_DOSStub_048c {
  strings:
    $key_048c = { 50 e4 [2] 24 fc [2] 63 fe [2] 24 ef [2] 6a e3 [2] 66 e9 [2] 71 e2 [2] 6a ac [2] 57 }

  condition:
    any of them
}