rule TTP_XOR_MULT_DOSStub_faa2 {
  strings:
    $key_faa2 = { ae ca [2] da d2 [2] 9d d0 [2] da c1 [2] 94 cd [2] 98 c7 [2] 8f cc [2] 94 82 [2] a9 }

  condition:
    any of them
}