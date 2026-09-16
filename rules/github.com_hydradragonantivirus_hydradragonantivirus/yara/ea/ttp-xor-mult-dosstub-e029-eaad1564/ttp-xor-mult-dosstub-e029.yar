rule TTP_XOR_MULT_DOSStub_e029 {
  strings:
    $key_e029 = { b4 41 [2] c0 59 [2] 87 5b [2] c0 4a [2] 8e 46 [2] 82 4c [2] 95 47 [2] 8e 09 [2] b3 }

  condition:
    any of them
}