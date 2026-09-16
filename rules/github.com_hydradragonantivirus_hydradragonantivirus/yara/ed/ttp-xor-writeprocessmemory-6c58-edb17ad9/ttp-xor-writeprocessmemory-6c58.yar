rule TTP_XOR_WriteProcessMemory_6c58 {
  strings:
    $key_6c58 = { 3b 2a [2] 09 08 [2] 0f 3d [2] 21 3d [2] 1e 21 }

  condition:
    any of them
}