rule TTP_XOR_MULT_DOSStub_0df2 {
  strings:
    $key_0df2 = { 59 9a [2] 2d 82 [2] 6a 80 [2] 2d 91 [2] 63 9d [2] 6f 97 [2] 78 9c [2] 63 d2 [2] 5e }

  condition:
    any of them
}