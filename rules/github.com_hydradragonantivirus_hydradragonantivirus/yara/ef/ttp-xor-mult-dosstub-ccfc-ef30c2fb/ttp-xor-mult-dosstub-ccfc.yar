rule TTP_XOR_MULT_DOSStub_ccfc {
  strings:
    $key_ccfc = { 98 94 [2] ec 8c [2] ab 8e [2] ec 9f [2] a2 93 [2] ae 99 [2] b9 92 [2] a2 dc [2] 9f }

  condition:
    any of them
}