rule TTP_XOR_WriteProcessMemory_cf23 {
  strings:
    $key_cf23 = { 98 51 [2] aa 73 [2] ac 46 [2] 82 46 [2] bd 5a }

  condition:
    any of them
}