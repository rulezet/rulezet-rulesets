rule TTP_XOR_MULT_DOSStub_61f2 {
  strings:
    $key_61f2 = { 35 9a [2] 41 82 [2] 06 80 [2] 41 91 [2] 0f 9d [2] 03 97 [2] 14 9c [2] 0f d2 [2] 32 }

  condition:
    any of them
}