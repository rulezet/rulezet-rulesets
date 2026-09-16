rule TTP_XOR_WriteProcessMemory_39a8 {
  strings:
    $key_39a8 = { 6e da [2] 5c f8 [2] 5a cd [2] 74 cd [2] 4b d1 }

  condition:
    any of them
}