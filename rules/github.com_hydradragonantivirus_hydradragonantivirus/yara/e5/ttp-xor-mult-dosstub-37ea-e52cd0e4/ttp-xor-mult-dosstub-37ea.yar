rule TTP_XOR_MULT_DOSStub_37ea {
  strings:
    $key_37ea = { 63 82 [2] 17 9a [2] 50 98 [2] 17 89 [2] 59 85 [2] 55 8f [2] 42 84 [2] 59 ca [2] 64 }

  condition:
    any of them
}