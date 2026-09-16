rule TTP_XOR_WriteProcessMemory_e86d {
  strings:
    $key_e86d = { bf 1f [2] 8d 3d [2] 8b 08 [2] a5 08 [2] 9a 14 }

  condition:
    any of them
}