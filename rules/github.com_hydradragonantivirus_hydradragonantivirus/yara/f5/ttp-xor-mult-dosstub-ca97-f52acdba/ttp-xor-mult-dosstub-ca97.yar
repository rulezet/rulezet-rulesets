rule TTP_XOR_MULT_DOSStub_ca97 {
  strings:
    $key_ca97 = { 9e ff [2] ea e7 [2] ad e5 [2] ea f4 [2] a4 f8 [2] a8 f2 [2] bf f9 [2] a4 b7 [2] 99 }

  condition:
    any of them
}