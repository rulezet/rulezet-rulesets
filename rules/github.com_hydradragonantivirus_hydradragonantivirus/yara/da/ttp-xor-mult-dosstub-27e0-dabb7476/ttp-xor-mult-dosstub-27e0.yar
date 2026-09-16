rule TTP_XOR_MULT_DOSStub_27e0 {
  strings:
    $key_27e0 = { 73 88 [2] 07 90 [2] 40 92 [2] 07 83 [2] 49 8f [2] 45 85 [2] 52 8e [2] 49 c0 [2] 74 }

  condition:
    any of them
}