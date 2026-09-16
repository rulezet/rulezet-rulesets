rule TTP_XOR_WriteProcessMemory_3220 {
  strings:
    $key_3220 = { 65 52 [2] 57 70 [2] 51 45 [2] 7f 45 [2] 40 59 }

  condition:
    any of them
}