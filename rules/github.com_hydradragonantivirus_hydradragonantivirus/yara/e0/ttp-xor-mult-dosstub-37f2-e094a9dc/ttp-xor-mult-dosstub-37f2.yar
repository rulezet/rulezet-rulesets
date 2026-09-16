rule TTP_XOR_MULT_DOSStub_37f2 {
  strings:
    $key_37f2 = { 63 9a [2] 17 82 [2] 50 80 [2] 17 91 [2] 59 9d [2] 55 97 [2] 42 9c [2] 59 d2 [2] 64 }

  condition:
    any of them
}