rule TTP_XOR_MULT_DOSStub_c181 {
  strings:
    $key_c181 = { 95 e9 [2] e1 f1 [2] a6 f3 [2] e1 e2 [2] af ee [2] a3 e4 [2] b4 ef [2] af a1 [2] 92 }

  condition:
    any of them
}