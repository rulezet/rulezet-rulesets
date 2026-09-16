rule TTP_XOR_WriteProcessMemory_03f8 {
  strings:
    $key_03f8 = { 54 8a [2] 66 a8 [2] 60 9d [2] 4e 9d [2] 71 81 }

  condition:
    any of them
}