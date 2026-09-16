rule TTP_XOR_MULT_DOSStub_caeb {
  strings:
    $key_caeb = { 9e 83 [2] ea 9b [2] ad 99 [2] ea 88 [2] a4 84 [2] a8 8e [2] bf 85 [2] a4 cb [2] 99 }

  condition:
    any of them
}