rule TTP_XOR_MULT_DOSStub_fbef {
  strings:
    $key_fbef = { af 87 [2] db 9f [2] 9c 9d [2] db 8c [2] 95 80 [2] 99 8a [2] 8e 81 [2] 95 cf [2] a8 }

  condition:
    any of them
}