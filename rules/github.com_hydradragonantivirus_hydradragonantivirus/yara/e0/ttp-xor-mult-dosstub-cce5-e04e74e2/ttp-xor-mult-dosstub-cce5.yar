rule TTP_XOR_MULT_DOSStub_cce5 {
  strings:
    $key_cce5 = { 98 8d [2] ec 95 [2] ab 97 [2] ec 86 [2] a2 8a [2] ae 80 [2] b9 8b [2] a2 c5 [2] 9f }

  condition:
    any of them
}