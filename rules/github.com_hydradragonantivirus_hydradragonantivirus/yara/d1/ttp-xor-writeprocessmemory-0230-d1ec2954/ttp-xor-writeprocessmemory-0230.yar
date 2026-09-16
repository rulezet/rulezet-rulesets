rule TTP_XOR_WriteProcessMemory_0230 {
  strings:
    $key_0230 = { 55 42 [2] 67 60 [2] 61 55 [2] 4f 55 [2] 70 49 }

  condition:
    any of them
}