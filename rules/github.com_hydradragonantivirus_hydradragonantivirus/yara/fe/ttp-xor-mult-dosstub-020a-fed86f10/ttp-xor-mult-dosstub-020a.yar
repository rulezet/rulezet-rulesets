rule TTP_XOR_MULT_DOSStub_020a {
  strings:
    $key_020a = { 56 62 [2] 22 7a [2] 65 78 [2] 22 69 [2] 6c 65 [2] 60 6f [2] 77 64 [2] 6c 2a [2] 51 }

  condition:
    any of them
}