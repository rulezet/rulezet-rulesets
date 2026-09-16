rule TTP_XOR_WriteProcessMemory_79a8 {
  strings:
    $key_79a8 = { 2e da [2] 1c f8 [2] 1a cd [2] 34 cd [2] 0b d1 }

  condition:
    any of them
}