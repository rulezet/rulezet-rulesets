rule TTP_XOR_MULT_DOSStub_e92f {
  strings:
    $key_e92f = { bd 47 [2] c9 5f [2] 8e 5d [2] c9 4c [2] 87 40 [2] 8b 4a [2] 9c 41 [2] 87 0f [2] ba }

  condition:
    any of them
}