rule TTP_XOR_MULT_DOSStub_8abf {
  strings:
    $key_8abf = { de d7 [2] aa cf [2] ed cd [2] aa dc [2] e4 d0 [2] e8 da [2] ff d1 [2] e4 9f [2] d9 }

  condition:
    any of them
}