rule TTP_XOR_WriteProcessMemory_03f9 {
  strings:
    $key_03f9 = { 54 8b [2] 66 a9 [2] 60 9c [2] 4e 9c [2] 71 80 }

  condition:
    any of them
}