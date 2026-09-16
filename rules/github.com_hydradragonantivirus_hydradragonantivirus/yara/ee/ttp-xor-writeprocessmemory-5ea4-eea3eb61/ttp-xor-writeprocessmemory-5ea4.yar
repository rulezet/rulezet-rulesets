rule TTP_XOR_WriteProcessMemory_5ea4 {
  strings:
    $key_5ea4 = { 09 d6 [2] 3b f4 [2] 3d c1 [2] 13 c1 [2] 2c dd }

  condition:
    any of them
}