rule TTP_XOR_WriteProcessMemory_0277 {
  strings:
    $key_0277 = { 55 05 [2] 67 27 [2] 61 12 [2] 4f 12 [2] 70 0e }

  condition:
    any of them
}