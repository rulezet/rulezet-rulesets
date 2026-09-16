rule TTP_XOR_MULT_DOSStub_f4e3 {
  strings:
    $key_f4e3 = { a0 8b [2] d4 93 [2] 93 91 [2] d4 80 [2] 9a 8c [2] 96 86 [2] 81 8d [2] 9a c3 [2] a7 }

  condition:
    any of them
}