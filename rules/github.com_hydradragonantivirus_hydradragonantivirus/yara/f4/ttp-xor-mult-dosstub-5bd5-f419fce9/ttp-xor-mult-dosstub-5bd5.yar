rule TTP_XOR_MULT_DOSStub_5bd5 {
  strings:
    $key_5bd5 = { 0f bd [2] 7b a5 [2] 3c a7 [2] 7b b6 [2] 35 ba [2] 39 b0 [2] 2e bb [2] 35 f5 [2] 08 }

  condition:
    any of them
}