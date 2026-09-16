rule TTP_XOR_WriteProcessMemory_0210 {
  strings:
    $key_0210 = { 55 62 [2] 67 40 [2] 61 75 [2] 4f 75 [2] 70 69 }

  condition:
    any of them
}