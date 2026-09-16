rule TTP_XOR_MULT_DOSStub_e30c {
  strings:
    $key_e30c = { b7 64 [2] c3 7c [2] 84 7e [2] c3 6f [2] 8d 63 [2] 81 69 [2] 96 62 [2] 8d 2c [2] b0 }

  condition:
    any of them
}