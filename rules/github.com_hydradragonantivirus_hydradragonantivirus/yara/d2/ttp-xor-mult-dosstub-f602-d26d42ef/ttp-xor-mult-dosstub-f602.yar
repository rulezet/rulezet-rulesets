rule TTP_XOR_MULT_DOSStub_f602 {
  strings:
    $key_f602 = { a2 6a [2] d6 72 [2] 91 70 [2] d6 61 [2] 98 6d [2] 94 67 [2] 83 6c [2] 98 22 [2] a5 }

  condition:
    any of them
}