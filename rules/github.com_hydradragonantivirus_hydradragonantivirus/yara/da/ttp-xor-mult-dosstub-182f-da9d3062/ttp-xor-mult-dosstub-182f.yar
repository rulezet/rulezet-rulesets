rule TTP_XOR_MULT_DOSStub_182f {
  strings:
    $key_182f = { 4c 47 [2] 38 5f [2] 7f 5d [2] 38 4c [2] 76 40 [2] 7a 4a [2] 6d 41 [2] 76 0f [2] 4b }

  condition:
    any of them
}