rule TTP_XOR_MULT_DOSStub_6a74 {
  strings:
    $key_6a74 = { 3e 1c [2] 4a 04 [2] 0d 06 [2] 4a 17 [2] 04 1b [2] 08 11 [2] 1f 1a [2] 04 54 [2] 39 }

  condition:
    any of them
}