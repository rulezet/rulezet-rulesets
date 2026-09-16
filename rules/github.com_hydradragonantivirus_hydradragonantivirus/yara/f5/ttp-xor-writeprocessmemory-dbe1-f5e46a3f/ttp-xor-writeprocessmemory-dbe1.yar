rule TTP_XOR_WriteProcessMemory_dbe1 {
  strings:
    $key_dbe1 = { 8c 93 [2] be b1 [2] b8 84 [2] 96 84 [2] a9 98 }

  condition:
    any of them
}