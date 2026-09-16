rule TTP_XOR_MULT_DOSStub_cce3 {
  strings:
    $key_cce3 = { 98 8b [2] ec 93 [2] ab 91 [2] ec 80 [2] a2 8c [2] ae 86 [2] b9 8d [2] a2 c3 [2] 9f }

  condition:
    any of them
}