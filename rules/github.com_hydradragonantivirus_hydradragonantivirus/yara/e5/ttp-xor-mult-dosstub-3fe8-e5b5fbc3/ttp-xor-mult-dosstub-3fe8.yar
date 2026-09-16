rule TTP_XOR_MULT_DOSStub_3fe8 {
  strings:
    $key_3fe8 = { 6b 80 [2] 1f 98 [2] 58 9a [2] 1f 8b [2] 51 87 [2] 5d 8d [2] 4a 86 [2] 51 c8 [2] 6c }

  condition:
    any of them
}