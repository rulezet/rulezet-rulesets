rule TTP_XOR_MULT_DOSStub_7db8 {
  strings:
    $key_7db8 = { 29 d0 [2] 5d c8 [2] 1a ca [2] 5d db [2] 13 d7 [2] 1f dd [2] 08 d6 [2] 13 98 [2] 2e }

  condition:
    any of them
}