rule TTP_XOR_MULT_DOSStub_c385 {
  strings:
    $key_c385 = { 97 ed [2] e3 f5 [2] a4 f7 [2] e3 e6 [2] ad ea [2] a1 e0 [2] b6 eb [2] ad a5 [2] 90 }

  condition:
    any of them
}