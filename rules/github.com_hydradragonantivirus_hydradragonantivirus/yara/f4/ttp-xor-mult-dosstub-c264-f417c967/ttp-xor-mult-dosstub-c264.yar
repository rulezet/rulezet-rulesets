rule TTP_XOR_MULT_DOSStub_c264 {
  strings:
    $key_c264 = { 96 0c [2] e2 14 [2] a5 16 [2] e2 07 [2] ac 0b [2] a0 01 [2] b7 0a [2] ac 44 [2] 91 }

  condition:
    any of them
}