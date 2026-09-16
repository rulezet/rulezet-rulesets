rule TTP_XOR_MULT_DOSStub_f6e3 {
  strings:
    $key_f6e3 = { a2 8b [2] d6 93 [2] 91 91 [2] d6 80 [2] 98 8c [2] 94 86 [2] 83 8d [2] 98 c3 [2] a5 }

  condition:
    any of them
}