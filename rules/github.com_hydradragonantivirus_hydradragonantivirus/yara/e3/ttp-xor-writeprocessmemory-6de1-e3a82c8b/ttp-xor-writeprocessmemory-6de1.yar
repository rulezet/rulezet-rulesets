rule TTP_XOR_WriteProcessMemory_6de1 {
  strings:
    $key_6de1 = { 3a 93 [2] 08 b1 [2] 0e 84 [2] 20 84 [2] 1f 98 }

  condition:
    any of them
}