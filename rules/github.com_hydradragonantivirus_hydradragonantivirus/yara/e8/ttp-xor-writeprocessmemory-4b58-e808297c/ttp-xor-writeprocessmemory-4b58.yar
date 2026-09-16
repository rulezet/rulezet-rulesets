rule TTP_XOR_WriteProcessMemory_4b58 {
  strings:
    $key_4b58 = { 1c 2a [2] 2e 08 [2] 28 3d [2] 06 3d [2] 39 21 }

  condition:
    any of them
}