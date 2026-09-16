rule TTP_XOR_MULT_DOSStub_7921 {
  strings:
    $key_7921 = { 2d 49 [2] 59 51 [2] 1e 53 [2] 59 42 [2] 17 4e [2] 1b 44 [2] 0c 4f [2] 17 01 [2] 2a }

  condition:
    any of them
}