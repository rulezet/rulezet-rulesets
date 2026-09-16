rule TTP_XOR_WriteProcessMemory_31f2 {
  strings:
    $key_31f2 = { 66 80 [2] 54 a2 [2] 52 97 [2] 7c 97 [2] 43 8b }

  condition:
    any of them
}