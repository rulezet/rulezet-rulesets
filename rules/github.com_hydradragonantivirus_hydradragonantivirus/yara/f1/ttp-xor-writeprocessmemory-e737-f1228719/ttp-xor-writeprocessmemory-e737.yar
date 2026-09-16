rule TTP_XOR_WriteProcessMemory_e737 {
  strings:
    $key_e737 = { b0 45 [2] 82 67 [2] 84 52 [2] aa 52 [2] 95 4e }

  condition:
    any of them
}