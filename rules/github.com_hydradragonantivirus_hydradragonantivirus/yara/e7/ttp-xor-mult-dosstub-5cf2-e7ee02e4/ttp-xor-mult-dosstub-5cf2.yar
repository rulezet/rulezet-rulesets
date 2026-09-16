rule TTP_XOR_MULT_DOSStub_5cf2 {
  strings:
    $key_5cf2 = { 08 9a [2] 7c 82 [2] 3b 80 [2] 7c 91 [2] 32 9d [2] 3e 97 [2] 29 9c [2] 32 d2 [2] 0f }

  condition:
    any of them
}