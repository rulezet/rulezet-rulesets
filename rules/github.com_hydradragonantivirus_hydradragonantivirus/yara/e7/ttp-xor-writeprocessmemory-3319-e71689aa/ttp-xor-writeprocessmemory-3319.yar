rule TTP_XOR_WriteProcessMemory_3319 {
  strings:
    $key_3319 = { 64 6b [2] 56 49 [2] 50 7c [2] 7e 7c [2] 41 60 }

  condition:
    any of them
}