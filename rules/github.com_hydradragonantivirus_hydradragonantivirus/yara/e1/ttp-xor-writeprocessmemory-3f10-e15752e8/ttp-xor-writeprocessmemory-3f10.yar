rule TTP_XOR_WriteProcessMemory_3f10 {
  strings:
    $key_3f10 = { 68 62 [2] 5a 40 [2] 5c 75 [2] 72 75 [2] 4d 69 }

  condition:
    any of them
}