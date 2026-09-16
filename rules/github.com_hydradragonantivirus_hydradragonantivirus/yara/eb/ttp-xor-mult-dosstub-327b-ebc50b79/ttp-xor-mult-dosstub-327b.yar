rule TTP_XOR_MULT_DOSStub_327b {
  strings:
    $key_327b = { 66 13 [2] 12 0b [2] 55 09 [2] 12 18 [2] 5c 14 [2] 50 1e [2] 47 15 [2] 5c 5b [2] 61 }

  condition:
    any of them
}