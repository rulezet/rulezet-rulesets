rule TTP_XOR_WriteProcessMemory_e131 {
  strings:
    $key_e131 = { b6 43 [2] 84 61 [2] 82 54 [2] ac 54 [2] 93 48 }

  condition:
    any of them
}