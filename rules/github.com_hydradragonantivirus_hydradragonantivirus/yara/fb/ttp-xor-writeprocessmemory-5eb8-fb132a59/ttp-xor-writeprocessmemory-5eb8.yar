rule TTP_XOR_WriteProcessMemory_5eb8 {
  strings:
    $key_5eb8 = { 09 ca [2] 3b e8 [2] 3d dd [2] 13 dd [2] 2c c1 }

  condition:
    any of them
}