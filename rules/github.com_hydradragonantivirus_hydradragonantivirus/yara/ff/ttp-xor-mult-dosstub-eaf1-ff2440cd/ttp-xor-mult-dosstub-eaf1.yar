rule TTP_XOR_MULT_DOSStub_eaf1 {
  strings:
    $key_eaf1 = { be 99 [2] ca 81 [2] 8d 83 [2] ca 92 [2] 84 9e [2] 88 94 [2] 9f 9f [2] 84 d1 [2] b9 }

  condition:
    any of them
}