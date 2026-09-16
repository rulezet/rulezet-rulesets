rule TTP_XOR_MULT_DOSStub_cca0 {
  strings:
    $key_cca0 = { 98 c8 [2] ec d0 [2] ab d2 [2] ec c3 [2] a2 cf [2] ae c5 [2] b9 ce [2] a2 80 [2] 9f }

  condition:
    any of them
}