rule TTP_XOR_MULT_DOSStub_513f {
  strings:
    $key_513f = { 05 57 [2] 71 4f [2] 36 4d [2] 71 5c [2] 3f 50 [2] 33 5a [2] 24 51 [2] 3f 1f [2] 02 }

  condition:
    any of them
}