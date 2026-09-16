rule TTP_XOR_WriteProcessMemory_42a8 {
  strings:
    $key_42a8 = { 15 da [2] 27 f8 [2] 21 cd [2] 0f cd [2] 30 d1 }

  condition:
    any of them
}