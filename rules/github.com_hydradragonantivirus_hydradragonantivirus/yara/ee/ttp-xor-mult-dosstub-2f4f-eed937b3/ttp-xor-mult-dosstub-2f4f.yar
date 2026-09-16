rule TTP_XOR_MULT_DOSStub_2f4f {
  strings:
    $key_2f4f = { 7b 27 [2] 0f 3f [2] 48 3d [2] 0f 2c [2] 41 20 [2] 4d 2a [2] 5a 21 [2] 41 6f [2] 7c }

  condition:
    any of them
}