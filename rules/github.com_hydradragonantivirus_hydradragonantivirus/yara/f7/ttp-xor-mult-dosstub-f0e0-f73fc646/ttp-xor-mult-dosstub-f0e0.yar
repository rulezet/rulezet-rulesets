rule TTP_XOR_MULT_DOSStub_f0e0 {
  strings:
    $key_f0e0 = { a4 88 [2] d0 90 [2] 97 92 [2] d0 83 [2] 9e 8f [2] 92 85 [2] 85 8e [2] 9e c0 [2] a3 }

  condition:
    any of them
}