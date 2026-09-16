rule TTP_XOR_WriteProcessMemory_ee50 {
  strings:
    $key_ee50 = { b9 22 [2] 8b 00 [2] 8d 35 [2] a3 35 [2] 9c 29 }

  condition:
    any of them
}