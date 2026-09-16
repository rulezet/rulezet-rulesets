rule TTP_XOR_MULT_DOSStub_f752 {
  strings:
    $key_f752 = { a3 3a [2] d7 22 [2] 90 20 [2] d7 31 [2] 99 3d [2] 95 37 [2] 82 3c [2] 99 72 [2] a4 }

  condition:
    any of them
}