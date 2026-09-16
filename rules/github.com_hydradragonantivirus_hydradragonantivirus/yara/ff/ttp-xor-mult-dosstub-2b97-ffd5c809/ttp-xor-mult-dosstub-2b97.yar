rule TTP_XOR_MULT_DOSStub_2b97 {
  strings:
    $key_2b97 = { 7f ff [2] 0b e7 [2] 4c e5 [2] 0b f4 [2] 45 f8 [2] 49 f2 [2] 5e f9 [2] 45 b7 [2] 78 }

  condition:
    any of them
}