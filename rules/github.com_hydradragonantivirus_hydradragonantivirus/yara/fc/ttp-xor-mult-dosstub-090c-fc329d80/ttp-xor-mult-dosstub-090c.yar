rule TTP_XOR_MULT_DOSStub_090c {
  strings:
    $key_090c = { 5d 64 [2] 29 7c [2] 6e 7e [2] 29 6f [2] 67 63 [2] 6b 69 [2] 7c 62 [2] 67 2c [2] 5a }

  condition:
    any of them
}