rule TTP_XOR_MULT_DOSStub_a8de {
  strings:
    $key_a8de = { fc b6 [2] 88 ae [2] cf ac [2] 88 bd [2] c6 b1 [2] ca bb [2] dd b0 [2] c6 fe [2] fb }

  condition:
    any of them
}