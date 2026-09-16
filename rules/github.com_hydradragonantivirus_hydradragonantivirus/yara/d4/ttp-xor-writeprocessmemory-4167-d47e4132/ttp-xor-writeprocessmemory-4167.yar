rule TTP_XOR_WriteProcessMemory_4167 {
  strings:
    $key_4167 = { 16 15 [2] 24 37 [2] 22 02 [2] 0c 02 [2] 33 1e }

  condition:
    any of them
}