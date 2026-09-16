rule TTP_XOR_WriteProcessMemory_0030 {
  strings:
    $key_0030 = { 57 42 [2] 65 60 [2] 63 55 [2] 4d 55 [2] 72 49 }

  condition:
    any of them
}