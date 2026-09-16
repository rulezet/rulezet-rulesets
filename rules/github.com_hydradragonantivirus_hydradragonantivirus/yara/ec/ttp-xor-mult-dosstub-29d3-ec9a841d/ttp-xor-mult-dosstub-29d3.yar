rule TTP_XOR_MULT_DOSStub_29d3 {
  strings:
    $key_29d3 = { 7d bb [2] 09 a3 [2] 4e a1 [2] 09 b0 [2] 47 bc [2] 4b b6 [2] 5c bd [2] 47 f3 [2] 7a }

  condition:
    any of them
}