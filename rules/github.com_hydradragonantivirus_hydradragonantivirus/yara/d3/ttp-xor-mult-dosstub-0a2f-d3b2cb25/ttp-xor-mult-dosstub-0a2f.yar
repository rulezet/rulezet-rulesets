rule TTP_XOR_MULT_DOSStub_0a2f {
  strings:
    $key_0a2f = { 5e 47 [2] 2a 5f [2] 6d 5d [2] 2a 4c [2] 64 40 [2] 68 4a [2] 7f 41 [2] 64 0f [2] 59 }

  condition:
    any of them
}