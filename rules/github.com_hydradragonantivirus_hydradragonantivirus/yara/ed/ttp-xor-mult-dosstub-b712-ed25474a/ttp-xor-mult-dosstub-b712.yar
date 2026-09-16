rule TTP_XOR_MULT_DOSStub_b712 {
  strings:
    $key_b712 = { e3 7a [2] 97 62 [2] d0 60 [2] 97 71 [2] d9 7d [2] d5 77 [2] c2 7c [2] d9 32 [2] e4 }

  condition:
    any of them
}