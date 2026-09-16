rule TTP_XOR_WriteProcessMemory_ee72 {
  strings:
    $key_ee72 = { b9 00 [2] 8b 22 [2] 8d 17 [2] a3 17 [2] 9c 0b }

  condition:
    any of them
}