rule TTP_XOR_MULT_DOSStub_68f2 {
  strings:
    $key_68f2 = { 3c 9a [2] 48 82 [2] 0f 80 [2] 48 91 [2] 06 9d [2] 0a 97 [2] 1d 9c [2] 06 d2 [2] 3b }

  condition:
    any of them
}