rule TTP_XOR_MULT_DOSStub_000d {
  strings:
    $key_000d = { 54 65 [2] 20 7d [2] 67 7f [2] 20 6e [2] 6e 62 [2] 62 68 [2] 75 63 [2] 6e 2d [2] 53 }

  condition:
    any of them
}