rule TTP_XOR_WriteProcessMemory_cf47 {
  strings:
    $key_cf47 = { 98 35 [2] aa 17 [2] ac 22 [2] 82 22 [2] bd 3e }

  condition:
    any of them
}