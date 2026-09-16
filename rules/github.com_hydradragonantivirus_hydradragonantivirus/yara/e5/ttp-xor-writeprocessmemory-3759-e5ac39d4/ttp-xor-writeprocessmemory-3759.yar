rule TTP_XOR_WriteProcessMemory_3759 {
  strings:
    $key_3759 = { 60 2b [2] 52 09 [2] 54 3c [2] 7a 3c [2] 45 20 }

  condition:
    any of them
}