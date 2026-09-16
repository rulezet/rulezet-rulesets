rule TTP_XOR_MULT_DOSStub_5ff7 {
  strings:
    $key_5ff7 = { 0b 9f [2] 7f 87 [2] 38 85 [2] 7f 94 [2] 31 98 [2] 3d 92 [2] 2a 99 [2] 31 d7 [2] 0c }

  condition:
    any of them
}