rule TTP_XOR_MULT_DOSStub_44f2 {
  strings:
    $key_44f2 = { 10 9a [2] 64 82 [2] 23 80 [2] 64 91 [2] 2a 9d [2] 26 97 [2] 31 9c [2] 2a d2 [2] 17 }

  condition:
    any of them
}