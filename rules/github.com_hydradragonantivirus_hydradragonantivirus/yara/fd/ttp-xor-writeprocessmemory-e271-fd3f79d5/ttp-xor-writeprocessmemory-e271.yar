rule TTP_XOR_WriteProcessMemory_e271 {
  strings:
    $key_e271 = { b5 03 [2] 87 21 [2] 81 14 [2] af 14 [2] 90 08 }

  condition:
    any of them
}