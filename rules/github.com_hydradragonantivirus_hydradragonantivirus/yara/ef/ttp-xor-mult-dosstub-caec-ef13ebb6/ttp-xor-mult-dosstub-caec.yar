rule TTP_XOR_MULT_DOSStub_caec {
  strings:
    $key_caec = { 9e 84 [2] ea 9c [2] ad 9e [2] ea 8f [2] a4 83 [2] a8 89 [2] bf 82 [2] a4 cc [2] 99 }

  condition:
    any of them
}