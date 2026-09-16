rule TTP_XOR_MULT_DOSStub_136c {
  strings:
    $key_136c = { 47 04 [2] 33 1c [2] 74 1e [2] 33 0f [2] 7d 03 [2] 71 09 [2] 66 02 [2] 7d 4c [2] 40 }

  condition:
    any of them
}