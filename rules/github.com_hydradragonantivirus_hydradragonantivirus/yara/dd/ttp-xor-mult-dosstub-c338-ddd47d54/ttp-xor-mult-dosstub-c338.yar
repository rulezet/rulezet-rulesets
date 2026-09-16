rule TTP_XOR_MULT_DOSStub_c338 {
  strings:
    $key_c338 = { 97 50 [2] e3 48 [2] a4 4a [2] e3 5b [2] ad 57 [2] a1 5d [2] b6 56 [2] ad 18 [2] 90 }

  condition:
    any of them
}