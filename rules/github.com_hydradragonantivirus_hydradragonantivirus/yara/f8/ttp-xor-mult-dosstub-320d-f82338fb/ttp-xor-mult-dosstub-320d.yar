rule TTP_XOR_MULT_DOSStub_320d {
  strings:
    $key_320d = { 66 65 [2] 12 7d [2] 55 7f [2] 12 6e [2] 5c 62 [2] 50 68 [2] 47 63 [2] 5c 2d [2] 61 }

  condition:
    any of them
}