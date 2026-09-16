rule TTP_XOR_MULT_DOSStub_cca7 {
  strings:
    $key_cca7 = { 98 cf [2] ec d7 [2] ab d5 [2] ec c4 [2] a2 c8 [2] ae c2 [2] b9 c9 [2] a2 87 [2] 9f }

  condition:
    any of them
}