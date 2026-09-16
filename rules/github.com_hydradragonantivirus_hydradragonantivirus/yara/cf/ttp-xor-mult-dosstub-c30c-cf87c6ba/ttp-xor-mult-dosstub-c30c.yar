rule TTP_XOR_MULT_DOSStub_c30c {
  strings:
    $key_c30c = { 97 64 [2] e3 7c [2] a4 7e [2] e3 6f [2] ad 63 [2] a1 69 [2] b6 62 [2] ad 2c [2] 90 }

  condition:
    any of them
}