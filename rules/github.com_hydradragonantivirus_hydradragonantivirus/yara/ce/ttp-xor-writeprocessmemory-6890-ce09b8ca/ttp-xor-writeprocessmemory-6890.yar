rule TTP_XOR_WriteProcessMemory_6890 {
  strings:
    $key_6890 = { 3f e2 [2] 0d c0 [2] 0b f5 [2] 25 f5 [2] 1a e9 }

  condition:
    any of them
}