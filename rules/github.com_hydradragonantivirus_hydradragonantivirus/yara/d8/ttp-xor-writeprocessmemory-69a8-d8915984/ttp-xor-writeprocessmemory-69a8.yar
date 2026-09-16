rule TTP_XOR_WriteProcessMemory_69a8 {
  strings:
    $key_69a8 = { 3e da [2] 0c f8 [2] 0a cd [2] 24 cd [2] 1b d1 }

  condition:
    any of them
}