rule TTP_XOR_MULT_DOSStub_6b0c {
  strings:
    $key_6b0c = { 3f 64 [2] 4b 7c [2] 0c 7e [2] 4b 6f [2] 05 63 [2] 09 69 [2] 1e 62 [2] 05 2c [2] 38 }

  condition:
    any of them
}