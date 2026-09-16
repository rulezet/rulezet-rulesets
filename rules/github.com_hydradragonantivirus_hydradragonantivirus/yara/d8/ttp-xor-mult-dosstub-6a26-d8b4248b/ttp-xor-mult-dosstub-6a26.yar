rule TTP_XOR_MULT_DOSStub_6a26 {
  strings:
    $key_6a26 = { 3e 4e [2] 4a 56 [2] 0d 54 [2] 4a 45 [2] 04 49 [2] 08 43 [2] 1f 48 [2] 04 06 [2] 39 }

  condition:
    any of them
}