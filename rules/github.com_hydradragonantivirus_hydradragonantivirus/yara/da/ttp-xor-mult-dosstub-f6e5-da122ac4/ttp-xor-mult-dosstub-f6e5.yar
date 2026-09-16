rule TTP_XOR_MULT_DOSStub_f6e5 {
  strings:
    $key_f6e5 = { a2 8d [2] d6 95 [2] 91 97 [2] d6 86 [2] 98 8a [2] 94 80 [2] 83 8b [2] 98 c5 [2] a5 }

  condition:
    any of them
}