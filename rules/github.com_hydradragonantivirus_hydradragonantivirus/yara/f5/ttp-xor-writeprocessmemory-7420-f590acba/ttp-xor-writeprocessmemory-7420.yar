rule TTP_XOR_WriteProcessMemory_7420 {
  strings:
    $key_7420 = { 23 52 [2] 11 70 [2] 17 45 [2] 39 45 [2] 06 59 }

  condition:
    any of them
}