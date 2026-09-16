rule TTP_XOR_MULT_DOSStub_baa2 {
  strings:
    $key_baa2 = { ee ca [2] 9a d2 [2] dd d0 [2] 9a c1 [2] d4 cd [2] d8 c7 [2] cf cc [2] d4 82 [2] e9 }

  condition:
    any of them
}