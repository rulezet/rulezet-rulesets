rule TTP_XOR_WriteProcessMemory_0270 {
  strings:
    $key_0270 = { 55 02 [2] 67 20 [2] 61 15 [2] 4f 15 [2] 70 09 }

  condition:
    any of them
}