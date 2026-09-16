rule TTP_XOR_WriteProcessMemory_cf37 {
  strings:
    $key_cf37 = { 98 45 [2] aa 67 [2] ac 52 [2] 82 52 [2] bd 4e }

  condition:
    any of them
}