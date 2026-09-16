rule TTP_XOR_MULT_DOSStub_580c {
  strings:
    $key_580c = { 0c 64 [2] 78 7c [2] 3f 7e [2] 78 6f [2] 36 63 [2] 3a 69 [2] 2d 62 [2] 36 2c [2] 0b }

  condition:
    any of them
}