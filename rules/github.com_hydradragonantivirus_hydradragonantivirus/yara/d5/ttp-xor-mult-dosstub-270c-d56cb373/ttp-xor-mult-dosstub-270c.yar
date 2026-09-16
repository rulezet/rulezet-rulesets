rule TTP_XOR_MULT_DOSStub_270c {
  strings:
    $key_270c = { 73 64 [2] 07 7c [2] 40 7e [2] 07 6f [2] 49 63 [2] 45 69 [2] 52 62 [2] 49 2c [2] 74 }

  condition:
    any of them
}