rule TTP_XOR_MULT_DOSStub_2be0 {
  strings:
    $key_2be0 = { 7f 88 [2] 0b 90 [2] 4c 92 [2] 0b 83 [2] 45 8f [2] 49 85 [2] 5e 8e [2] 45 c0 [2] 78 }

  condition:
    any of them
}