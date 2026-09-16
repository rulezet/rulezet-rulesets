rule TTP_XOR_MULT_DOSStub_aefe {
  strings:
    $key_aefe = { fa 96 [2] 8e 8e [2] c9 8c [2] 8e 9d [2] c0 91 [2] cc 9b [2] db 90 [2] c0 de [2] fd }

  condition:
    any of them
}