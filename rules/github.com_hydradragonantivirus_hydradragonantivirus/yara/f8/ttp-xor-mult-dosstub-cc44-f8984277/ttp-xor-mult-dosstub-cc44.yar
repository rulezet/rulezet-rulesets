rule TTP_XOR_MULT_DOSStub_cc44 {
  strings:
    $key_cc44 = { 98 2c [2] ec 34 [2] ab 36 [2] ec 27 [2] a2 2b [2] ae 21 [2] b9 2a [2] a2 64 [2] 9f }

  condition:
    any of them
}