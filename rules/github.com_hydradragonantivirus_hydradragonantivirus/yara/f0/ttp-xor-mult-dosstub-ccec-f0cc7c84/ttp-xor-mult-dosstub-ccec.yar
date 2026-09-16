rule TTP_XOR_MULT_DOSStub_ccec {
  strings:
    $key_ccec = { 98 84 [2] ec 9c [2] ab 9e [2] ec 8f [2] a2 83 [2] ae 89 [2] b9 82 [2] a2 cc [2] 9f }

  condition:
    any of them
}