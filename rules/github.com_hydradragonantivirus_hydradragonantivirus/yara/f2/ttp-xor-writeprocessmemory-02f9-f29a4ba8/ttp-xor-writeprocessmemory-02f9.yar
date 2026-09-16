rule TTP_XOR_WriteProcessMemory_02f9 {
  strings:
    $key_02f9 = { 55 8b [2] 67 a9 [2] 61 9c [2] 4f 9c [2] 70 80 }

  condition:
    any of them
}