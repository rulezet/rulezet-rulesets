rule TTP_XOR_MULT_DOSStub_5fe3 {
  strings:
    $key_5fe3 = { 0b 8b [2] 7f 93 [2] 38 91 [2] 7f 80 [2] 31 8c [2] 3d 86 [2] 2a 8d [2] 31 c3 [2] 0c }

  condition:
    any of them
}