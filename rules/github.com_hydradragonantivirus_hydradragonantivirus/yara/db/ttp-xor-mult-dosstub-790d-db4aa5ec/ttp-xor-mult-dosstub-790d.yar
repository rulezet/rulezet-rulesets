rule TTP_XOR_MULT_DOSStub_790d {
  strings:
    $key_790d = { 2d 65 [2] 59 7d [2] 1e 7f [2] 59 6e [2] 17 62 [2] 1b 68 [2] 0c 63 [2] 17 2d [2] 2a }

  condition:
    any of them
}