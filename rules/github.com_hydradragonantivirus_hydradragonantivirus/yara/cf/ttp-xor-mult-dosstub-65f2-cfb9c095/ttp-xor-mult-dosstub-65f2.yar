rule TTP_XOR_MULT_DOSStub_65f2 {
  strings:
    $key_65f2 = { 31 9a [2] 45 82 [2] 02 80 [2] 45 91 [2] 0b 9d [2] 07 97 [2] 10 9c [2] 0b d2 [2] 36 }

  condition:
    any of them
}