rule TTP_XOR_WriteProcessMemory_ab38 {
  strings:
    $key_ab38 = { fc 4a [2] ce 68 [2] c8 5d [2] e6 5d [2] d9 41 }

  condition:
    any of them
}