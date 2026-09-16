rule TTP_XOR_MULT_DOSStub_cce2 {
  strings:
    $key_cce2 = { 98 8a [2] ec 92 [2] ab 90 [2] ec 81 [2] a2 8d [2] ae 87 [2] b9 8c [2] a2 c2 [2] 9f }

  condition:
    any of them
}