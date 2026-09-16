rule TTP_XOR_MULT_DOSStub_f656 {
  strings:
    $key_f656 = { a2 3e [2] d6 26 [2] 91 24 [2] d6 35 [2] 98 39 [2] 94 33 [2] 83 38 [2] 98 76 [2] a5 }

  condition:
    any of them
}