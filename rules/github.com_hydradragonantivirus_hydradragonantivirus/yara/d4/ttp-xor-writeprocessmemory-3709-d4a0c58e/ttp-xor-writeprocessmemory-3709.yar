rule TTP_XOR_WriteProcessMemory_3709 {
  strings:
    $key_3709 = { 60 7b [2] 52 59 [2] 54 6c [2] 7a 6c [2] 45 70 }

  condition:
    any of them
}