rule TTP_XOR_MULT_DOSStub_f122 {
  strings:
    $key_f122 = { a5 4a [2] d1 52 [2] 96 50 [2] d1 41 [2] 9f 4d [2] 93 47 [2] 84 4c [2] 9f 02 [2] a2 }

  condition:
    any of them
}