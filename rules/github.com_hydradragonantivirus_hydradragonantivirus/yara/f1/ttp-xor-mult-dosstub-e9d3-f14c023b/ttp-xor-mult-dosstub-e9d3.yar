rule TTP_XOR_MULT_DOSStub_e9d3 {
  strings:
    $key_e9d3 = { bd bb [2] c9 a3 [2] 8e a1 [2] c9 b0 [2] 87 bc [2] 8b b6 [2] 9c bd [2] 87 f3 [2] ba }

  condition:
    any of them
}