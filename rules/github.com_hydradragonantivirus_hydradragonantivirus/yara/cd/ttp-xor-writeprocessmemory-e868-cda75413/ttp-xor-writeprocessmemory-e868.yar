rule TTP_XOR_WriteProcessMemory_e868 {
  strings:
    $key_e868 = { bf 1a [2] 8d 38 [2] 8b 0d [2] a5 0d [2] 9a 11 }

  condition:
    any of them
}