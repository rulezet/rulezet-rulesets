rule TTP_XOR_MULT_DOSStub_f658 {
  strings:
    $key_f658 = { a2 30 [2] d6 28 [2] 91 2a [2] d6 3b [2] 98 37 [2] 94 3d [2] 83 36 [2] 98 78 [2] a5 }

  condition:
    any of them
}