rule TTP_XOR_MULT_DOSStub_3057 {
  strings:
    $key_3057 = { 64 3f [2] 10 27 [2] 57 25 [2] 10 34 [2] 5e 38 [2] 52 32 [2] 45 39 [2] 5e 77 [2] 63 }

  condition:
    any of them
}