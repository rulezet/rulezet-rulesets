rule TTP_XOR_MULT_DOSStub_6a1f {
  strings:
    $key_6a1f = { 3e 77 [2] 4a 6f [2] 0d 6d [2] 4a 7c [2] 04 70 [2] 08 7a [2] 1f 71 [2] 04 3f [2] 39 }

  condition:
    any of them
}