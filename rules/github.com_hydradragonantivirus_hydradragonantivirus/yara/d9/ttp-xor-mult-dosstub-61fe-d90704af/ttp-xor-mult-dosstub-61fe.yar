rule TTP_XOR_MULT_DOSStub_61fe {
  strings:
    $key_61fe = { 35 96 [2] 41 8e [2] 06 8c [2] 41 9d [2] 0f 91 [2] 03 9b [2] 14 90 [2] 0f de [2] 32 }

  condition:
    any of them
}