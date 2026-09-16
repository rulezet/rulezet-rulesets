rule TTP_XOR_WriteProcessMemory_2719 {
  strings:
    $key_2719 = { 70 6b [2] 42 49 [2] 44 7c [2] 6a 7c [2] 55 60 }

  condition:
    any of them
}