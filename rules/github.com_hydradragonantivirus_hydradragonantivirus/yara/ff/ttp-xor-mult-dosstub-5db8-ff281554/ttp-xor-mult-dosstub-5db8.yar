rule TTP_XOR_MULT_DOSStub_5db8 {
  strings:
    $key_5db8 = { 09 d0 [2] 7d c8 [2] 3a ca [2] 7d db [2] 33 d7 [2] 3f dd [2] 28 d6 [2] 33 98 [2] 0e }

  condition:
    any of them
}