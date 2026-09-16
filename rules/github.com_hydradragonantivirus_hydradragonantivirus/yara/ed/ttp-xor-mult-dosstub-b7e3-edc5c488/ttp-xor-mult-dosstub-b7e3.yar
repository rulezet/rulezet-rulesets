rule TTP_XOR_MULT_DOSStub_b7e3 {
  strings:
    $key_b7e3 = { e3 8b [2] 97 93 [2] d0 91 [2] 97 80 [2] d9 8c [2] d5 86 [2] c2 8d [2] d9 c3 [2] e4 }

  condition:
    any of them
}