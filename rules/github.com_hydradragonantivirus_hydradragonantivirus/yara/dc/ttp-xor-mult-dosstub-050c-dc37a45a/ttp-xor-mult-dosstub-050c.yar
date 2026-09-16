rule TTP_XOR_MULT_DOSStub_050c {
  strings:
    $key_050c = { 51 64 [2] 25 7c [2] 62 7e [2] 25 6f [2] 6b 63 [2] 67 69 [2] 70 62 [2] 6b 2c [2] 56 }

  condition:
    any of them
}