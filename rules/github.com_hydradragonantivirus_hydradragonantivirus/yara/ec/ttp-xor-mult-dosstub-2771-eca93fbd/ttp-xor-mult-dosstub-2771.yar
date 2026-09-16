rule TTP_XOR_MULT_DOSStub_2771 {
  strings:
    $key_2771 = { 73 19 [2] 07 01 [2] 40 03 [2] 07 12 [2] 49 1e [2] 45 14 [2] 52 1f [2] 49 51 [2] 74 }

  condition:
    any of them
}