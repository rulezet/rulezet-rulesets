rule TTP_XOR_MULT_DOSStub_61de {
  strings:
    $key_61de = { 35 b6 [2] 41 ae [2] 06 ac [2] 41 bd [2] 0f b1 [2] 03 bb [2] 14 b0 [2] 0f fe [2] 32 }

  condition:
    any of them
}