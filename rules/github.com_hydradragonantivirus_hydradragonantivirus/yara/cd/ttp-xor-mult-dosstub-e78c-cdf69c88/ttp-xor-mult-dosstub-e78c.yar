rule TTP_XOR_MULT_DOSStub_e78c {
  strings:
    $key_e78c = { b3 e4 [2] c7 fc [2] 80 fe [2] c7 ef [2] 89 e3 [2] 85 e9 [2] 92 e2 [2] 89 ac [2] b4 }

  condition:
    any of them
}