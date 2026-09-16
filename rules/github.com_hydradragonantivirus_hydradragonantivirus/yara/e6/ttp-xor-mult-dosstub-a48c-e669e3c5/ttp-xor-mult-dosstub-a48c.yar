rule TTP_XOR_MULT_DOSStub_a48c {
  strings:
    $key_a48c = { f0 e4 [2] 84 fc [2] c3 fe [2] 84 ef [2] ca e3 [2] c6 e9 [2] d1 e2 [2] ca ac [2] f7 }

  condition:
    any of them
}