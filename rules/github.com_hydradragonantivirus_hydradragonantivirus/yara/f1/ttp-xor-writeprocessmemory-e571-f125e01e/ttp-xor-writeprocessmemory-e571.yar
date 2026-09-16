rule TTP_XOR_WriteProcessMemory_e571 {
  strings:
    $key_e571 = { b2 03 [2] 80 21 [2] 86 14 [2] a8 14 [2] 97 08 }

  condition:
    any of them
}