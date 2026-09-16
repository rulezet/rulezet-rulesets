rule TTP_XOR_MULT_DOSStub_eaa3 {
  strings:
    $key_eaa3 = { be cb [2] ca d3 [2] 8d d1 [2] ca c0 [2] 84 cc [2] 88 c6 [2] 9f cd [2] 84 83 [2] b9 }

  condition:
    any of them
}