rule TTP_XOR_MULT_DOSStub_132f {
  strings:
    $key_132f = { 47 47 [2] 33 5f [2] 74 5d [2] 33 4c [2] 7d 40 [2] 71 4a [2] 66 41 [2] 7d 0f [2] 40 }

  condition:
    any of them
}