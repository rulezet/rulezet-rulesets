rule TTP_XOR_MULT_DOSStub_f6f5 {
  strings:
    $key_f6f5 = { a2 9d [2] d6 85 [2] 91 87 [2] d6 96 [2] 98 9a [2] 94 90 [2] 83 9b [2] 98 d5 [2] a5 }

  condition:
    any of them
}