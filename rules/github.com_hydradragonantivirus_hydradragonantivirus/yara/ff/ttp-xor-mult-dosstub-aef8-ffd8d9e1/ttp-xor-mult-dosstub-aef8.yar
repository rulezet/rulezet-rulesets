rule TTP_XOR_MULT_DOSStub_aef8 {
  strings:
    $key_aef8 = { fa 90 [2] 8e 88 [2] c9 8a [2] 8e 9b [2] c0 97 [2] cc 9d [2] db 96 [2] c0 d8 [2] fd }

  condition:
    any of them
}