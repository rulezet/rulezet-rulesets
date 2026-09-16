rule TTP_XOR_WriteProcessMemory_3120 {
  strings:
    $key_3120 = { 66 52 [2] 54 70 [2] 52 45 [2] 7c 45 [2] 43 59 }

  condition:
    any of them
}