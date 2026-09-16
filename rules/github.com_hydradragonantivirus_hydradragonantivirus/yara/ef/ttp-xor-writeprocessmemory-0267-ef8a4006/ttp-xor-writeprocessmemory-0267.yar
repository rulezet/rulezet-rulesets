rule TTP_XOR_WriteProcessMemory_0267 {
  strings:
    $key_0267 = { 55 15 [2] 67 37 [2] 61 02 [2] 4f 02 [2] 70 1e }

  condition:
    any of them
}