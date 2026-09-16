rule TTP_XOR_WriteProcessMemory_7fe1 {
  strings:
    $key_7fe1 = { 28 93 [2] 1a b1 [2] 1c 84 [2] 32 84 [2] 0d 98 }

  condition:
    any of them
}