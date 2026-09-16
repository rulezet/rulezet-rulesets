rule TTP_XOR_MULT_DOSStub_e81d {
  strings:
    $key_e81d = { bc 75 [2] c8 6d [2] 8f 6f [2] c8 7e [2] 86 72 [2] 8a 78 [2] 9d 73 [2] 86 3d [2] bb }

  condition:
    any of them
}