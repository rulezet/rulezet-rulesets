rule TTP_XOR_WriteProcessMemory_1ea4 {
  strings:
    $key_1ea4 = { 49 d6 [2] 7b f4 [2] 7d c1 [2] 53 c1 [2] 6c dd }

  condition:
    any of them
}