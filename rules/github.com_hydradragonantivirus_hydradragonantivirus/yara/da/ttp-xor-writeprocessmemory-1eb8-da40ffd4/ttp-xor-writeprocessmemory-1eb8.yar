rule TTP_XOR_WriteProcessMemory_1eb8 {
  strings:
    $key_1eb8 = { 49 ca [2] 7b e8 [2] 7d dd [2] 53 dd [2] 6c c1 }

  condition:
    any of them
}