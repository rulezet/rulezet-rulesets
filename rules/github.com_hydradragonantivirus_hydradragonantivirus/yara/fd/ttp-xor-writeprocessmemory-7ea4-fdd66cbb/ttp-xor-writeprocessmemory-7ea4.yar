rule TTP_XOR_WriteProcessMemory_7ea4 {
  strings:
    $key_7ea4 = { 29 d6 [2] 1b f4 [2] 1d c1 [2] 33 c1 [2] 0c dd }

  condition:
    any of them
}