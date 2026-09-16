rule TTP_XOR_MULT_DOSStub_5fe8 {
  strings:
    $key_5fe8 = { 0b 80 [2] 7f 98 [2] 38 9a [2] 7f 8b [2] 31 87 [2] 3d 8d [2] 2a 86 [2] 31 c8 [2] 0c }

  condition:
    any of them
}