rule TTP_XOR_WriteProcessMemory_4ce1 {
  strings:
    $key_4ce1 = { 1b 93 [2] 29 b1 [2] 2f 84 [2] 01 84 [2] 3e 98 }

  condition:
    any of them
}