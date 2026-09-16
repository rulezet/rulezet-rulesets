rule TTP_XOR_WriteProcessMemory_e171 {
  strings:
    $key_e171 = { b6 03 [2] 84 21 [2] 82 14 [2] ac 14 [2] 93 08 }

  condition:
    any of them
}