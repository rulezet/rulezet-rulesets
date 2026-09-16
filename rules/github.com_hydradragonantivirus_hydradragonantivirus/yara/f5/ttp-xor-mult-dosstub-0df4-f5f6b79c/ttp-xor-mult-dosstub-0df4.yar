rule TTP_XOR_MULT_DOSStub_0df4 {
  strings:
    $key_0df4 = { 59 9c [2] 2d 84 [2] 6a 86 [2] 2d 97 [2] 63 9b [2] 6f 91 [2] 78 9a [2] 63 d4 [2] 5e }

  condition:
    any of them
}