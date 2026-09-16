rule TTP_XOR_MULT_DOSStub_5ff0 {
  strings:
    $key_5ff0 = { 0b 98 [2] 7f 80 [2] 38 82 [2] 7f 93 [2] 31 9f [2] 3d 95 [2] 2a 9e [2] 31 d0 [2] 0c }

  condition:
    any of them
}