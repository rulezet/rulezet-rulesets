rule TTP_XOR_WriteProcessMemory_1e8d {
  strings:
    $key_1e8d = { 49 ff [2] 7b dd [2] 7d e8 [2] 53 e8 [2] 6c f4 }

  condition:
    any of them
}