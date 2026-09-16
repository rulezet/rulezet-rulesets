rule TTP_XOR_WriteProcessMemory_05f9 {
  strings:
    $key_05f9 = { 52 8b [2] 60 a9 [2] 66 9c [2] 48 9c [2] 77 80 }

  condition:
    any of them
}