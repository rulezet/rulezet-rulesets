rule TTP_XOR_MULT_DOSStub_f6e8 {
  strings:
    $key_f6e8 = { a2 80 [2] d6 98 [2] 91 9a [2] d6 8b [2] 98 87 [2] 94 8d [2] 83 86 [2] 98 c8 [2] a5 }

  condition:
    any of them
}