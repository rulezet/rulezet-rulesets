rule TTP_XOR_WriteProcessMemory_0225 {
  strings:
    $key_0225 = { 55 57 [2] 67 75 [2] 61 40 [2] 4f 40 [2] 70 5c }

  condition:
    any of them
}