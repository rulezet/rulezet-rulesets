rule TTP_XOR_WriteProcessMemory_6220 {
  strings:
    $key_6220 = { 35 52 [2] 07 70 [2] 01 45 [2] 2f 45 [2] 10 59 }

  condition:
    any of them
}