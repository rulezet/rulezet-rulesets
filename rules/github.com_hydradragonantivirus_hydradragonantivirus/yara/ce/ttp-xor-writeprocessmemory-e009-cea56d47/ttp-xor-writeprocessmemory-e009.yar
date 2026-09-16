rule TTP_XOR_WriteProcessMemory_e009 {
  strings:
    $key_e009 = { b7 7b [2] 85 59 [2] 83 6c [2] ad 6c [2] 92 70 }

  condition:
    any of them
}