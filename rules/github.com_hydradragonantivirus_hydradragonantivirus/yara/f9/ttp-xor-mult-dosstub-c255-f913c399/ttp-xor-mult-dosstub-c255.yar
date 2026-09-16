rule TTP_XOR_MULT_DOSStub_c255 {
  strings:
    $key_c255 = { 96 3d [2] e2 25 [2] a5 27 [2] e2 36 [2] ac 3a [2] a0 30 [2] b7 3b [2] ac 75 [2] 91 }

  condition:
    any of them
}