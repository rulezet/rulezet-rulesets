rule TTP_XOR_WriteProcessMemory_2be2 {
  strings:
    $key_2be2 = { 7c 90 [2] 4e b2 [2] 48 87 [2] 66 87 [2] 59 9b }

  condition:
    any of them
}