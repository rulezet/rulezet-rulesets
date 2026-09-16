rule TTP_XOR_MULT_DOSStub_d42f {
  strings:
    $key_d42f = { 80 47 [2] f4 5f [2] b3 5d [2] f4 4c [2] ba 40 [2] b6 4a [2] a1 41 [2] ba 0f [2] 87 }

  condition:
    any of them
}