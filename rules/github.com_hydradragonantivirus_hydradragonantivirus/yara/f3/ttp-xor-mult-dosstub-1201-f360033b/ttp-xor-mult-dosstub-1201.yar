rule TTP_XOR_MULT_DOSStub_1201 {
  strings:
    $key_1201 = { 46 69 [2] 32 71 [2] 75 73 [2] 32 62 [2] 7c 6e [2] 70 64 [2] 67 6f [2] 7c 21 [2] 41 }

  condition:
    any of them
}