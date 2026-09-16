rule TTP_XOR_MULT_DOSStub_e513 {
  strings:
    $key_e513 = { b1 7b [2] c5 63 [2] 82 61 [2] c5 70 [2] 8b 7c [2] 87 76 [2] 90 7d [2] 8b 33 [2] b6 }

  condition:
    any of them
}