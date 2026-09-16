rule TTP_XOR_MULT_DOSStub_e88c {
  strings:
    $key_e88c = { bc e4 [2] c8 fc [2] 8f fe [2] c8 ef [2] 86 e3 [2] 8a e9 [2] 9d e2 [2] 86 ac [2] bb }

  condition:
    any of them
}