rule TTP_XOR_MULT_DOSStub_e1fe {
  strings:
    $key_e1fe = { b5 96 [2] c1 8e [2] 86 8c [2] c1 9d [2] 8f 91 [2] 83 9b [2] 94 90 [2] 8f de [2] b2 }

  condition:
    any of them
}