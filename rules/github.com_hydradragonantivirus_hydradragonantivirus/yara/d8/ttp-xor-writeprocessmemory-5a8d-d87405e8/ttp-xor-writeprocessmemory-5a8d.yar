rule TTP_XOR_WriteProcessMemory_5a8d {
  strings:
    $key_5a8d = { 0d ff [2] 3f dd [2] 39 e8 [2] 17 e8 [2] 28 f4 }

  condition:
    any of them
}