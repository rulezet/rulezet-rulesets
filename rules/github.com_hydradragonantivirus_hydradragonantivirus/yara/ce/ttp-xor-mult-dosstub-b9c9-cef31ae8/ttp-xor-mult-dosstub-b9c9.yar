rule TTP_XOR_MULT_DOSStub_b9c9 {
  strings:
    $key_b9c9 = { ed a1 [2] 99 b9 [2] de bb [2] 99 aa [2] d7 a6 [2] db ac [2] cc a7 [2] d7 e9 [2] ea }

  condition:
    any of them
}