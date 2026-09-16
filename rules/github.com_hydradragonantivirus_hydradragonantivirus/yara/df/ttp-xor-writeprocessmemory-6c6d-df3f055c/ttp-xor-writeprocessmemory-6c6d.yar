rule TTP_XOR_WriteProcessMemory_6c6d {
  strings:
    $key_6c6d = { 3b 1f [2] 09 3d [2] 0f 08 [2] 21 08 [2] 1e 14 }

  condition:
    any of them
}