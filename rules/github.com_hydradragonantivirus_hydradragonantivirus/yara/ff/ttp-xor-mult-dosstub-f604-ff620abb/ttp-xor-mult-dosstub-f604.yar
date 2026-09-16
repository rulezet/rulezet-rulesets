rule TTP_XOR_MULT_DOSStub_f604 {
  strings:
    $key_f604 = { a2 6c [2] d6 74 [2] 91 76 [2] d6 67 [2] 98 6b [2] 94 61 [2] 83 6a [2] 98 24 [2] a5 }

  condition:
    any of them
}