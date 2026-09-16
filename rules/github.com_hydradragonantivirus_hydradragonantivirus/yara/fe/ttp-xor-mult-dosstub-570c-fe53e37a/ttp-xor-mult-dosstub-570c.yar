rule TTP_XOR_MULT_DOSStub_570c {
  strings:
    $key_570c = { 03 64 [2] 77 7c [2] 30 7e [2] 77 6f [2] 39 63 [2] 35 69 [2] 22 62 [2] 39 2c [2] 04 }

  condition:
    any of them
}