rule TTP_XOR_WriteProcessMemory_e143 {
  strings:
    $key_e143 = { b6 31 [2] 84 13 [2] 82 26 [2] ac 26 [2] 93 3a }

  condition:
    any of them
}