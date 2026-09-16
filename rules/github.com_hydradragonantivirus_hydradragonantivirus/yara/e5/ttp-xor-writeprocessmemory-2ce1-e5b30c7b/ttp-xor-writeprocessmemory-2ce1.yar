rule TTP_XOR_WriteProcessMemory_2ce1 {
  strings:
    $key_2ce1 = { 7b 93 [2] 49 b1 [2] 4f 84 [2] 61 84 [2] 5e 98 }

  condition:
    any of them
}