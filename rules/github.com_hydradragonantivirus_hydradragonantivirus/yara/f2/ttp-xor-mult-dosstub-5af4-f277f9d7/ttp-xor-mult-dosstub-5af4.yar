rule TTP_XOR_MULT_DOSStub_5af4 {
  strings:
    $key_5af4 = { 0e 9c [2] 7a 84 [2] 3d 86 [2] 7a 97 [2] 34 9b [2] 38 91 [2] 2f 9a [2] 34 d4 [2] 09 }

  condition:
    any of them
}