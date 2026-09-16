rule TTP_XOR_WriteProcessMemory_2b20 {
  strings:
    $key_2b20 = { 7c 52 [2] 4e 70 [2] 48 45 [2] 66 45 [2] 59 59 }

  condition:
    any of them
}