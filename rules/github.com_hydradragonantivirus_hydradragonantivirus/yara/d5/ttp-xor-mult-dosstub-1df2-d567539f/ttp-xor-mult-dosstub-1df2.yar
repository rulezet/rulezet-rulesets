rule TTP_XOR_MULT_DOSStub_1df2 {
  strings:
    $key_1df2 = { 49 9a [2] 3d 82 [2] 7a 80 [2] 3d 91 [2] 73 9d [2] 7f 97 [2] 68 9c [2] 73 d2 [2] 4e }

  condition:
    any of them
}