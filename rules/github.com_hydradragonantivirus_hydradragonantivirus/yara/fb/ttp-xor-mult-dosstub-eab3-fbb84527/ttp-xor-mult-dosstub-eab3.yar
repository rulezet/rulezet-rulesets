rule TTP_XOR_MULT_DOSStub_eab3 {
  strings:
    $key_eab3 = { be db [2] ca c3 [2] 8d c1 [2] ca d0 [2] 84 dc [2] 88 d6 [2] 9f dd [2] 84 93 [2] b9 }

  condition:
    any of them
}