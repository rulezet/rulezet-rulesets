rule TTP_XOR_MULT_DOSStub_c103 {
  strings:
    $key_c103 = { 95 6b [2] e1 73 [2] a6 71 [2] e1 60 [2] af 6c [2] a3 66 [2] b4 6d [2] af 23 [2] 92 }

  condition:
    any of them
}