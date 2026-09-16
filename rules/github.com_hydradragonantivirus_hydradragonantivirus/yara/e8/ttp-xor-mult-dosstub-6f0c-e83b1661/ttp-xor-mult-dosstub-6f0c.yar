rule TTP_XOR_MULT_DOSStub_6f0c {
  strings:
    $key_6f0c = { 3b 64 [2] 4f 7c [2] 08 7e [2] 4f 6f [2] 01 63 [2] 0d 69 [2] 1a 62 [2] 01 2c [2] 3c }

  condition:
    any of them
}