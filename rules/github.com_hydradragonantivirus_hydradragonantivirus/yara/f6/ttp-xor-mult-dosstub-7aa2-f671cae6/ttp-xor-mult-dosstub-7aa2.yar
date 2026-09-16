rule TTP_XOR_MULT_DOSStub_7aa2 {
  strings:
    $key_7aa2 = { 2e ca [2] 5a d2 [2] 1d d0 [2] 5a c1 [2] 14 cd [2] 18 c7 [2] 0f cc [2] 14 82 [2] 29 }

  condition:
    any of them
}