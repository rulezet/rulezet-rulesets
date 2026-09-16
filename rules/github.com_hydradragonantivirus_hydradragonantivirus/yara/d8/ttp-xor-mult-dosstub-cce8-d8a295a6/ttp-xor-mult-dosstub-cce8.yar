rule TTP_XOR_MULT_DOSStub_cce8 {
  strings:
    $key_cce8 = { 98 80 [2] ec 98 [2] ab 9a [2] ec 8b [2] a2 87 [2] ae 8d [2] b9 86 [2] a2 c8 [2] 9f }

  condition:
    any of them
}