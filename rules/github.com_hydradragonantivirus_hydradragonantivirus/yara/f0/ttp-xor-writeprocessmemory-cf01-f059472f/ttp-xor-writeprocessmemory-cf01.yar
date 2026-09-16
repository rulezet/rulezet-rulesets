rule TTP_XOR_WriteProcessMemory_cf01 {
  strings:
    $key_cf01 = { 98 73 [2] aa 51 [2] ac 64 [2] 82 64 [2] bd 78 }

  condition:
    any of them
}