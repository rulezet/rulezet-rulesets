rule TTP_XOR_WriteProcessMemory_788d {
  strings:
    $key_788d = { 2f ff [2] 1d dd [2] 1b e8 [2] 35 e8 [2] 0a f4 }

  condition:
    any of them
}