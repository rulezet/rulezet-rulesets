rule TTP_XOR_MULT_DOSStub_4919 {
  strings:
    $key_4919 = { 1d 71 [2] 69 69 [2] 2e 6b [2] 69 7a [2] 27 76 [2] 2b 7c [2] 3c 77 [2] 27 39 [2] 1a }

  condition:
    any of them
}