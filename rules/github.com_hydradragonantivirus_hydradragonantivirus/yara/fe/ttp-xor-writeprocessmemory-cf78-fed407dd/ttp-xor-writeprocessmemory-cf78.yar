rule TTP_XOR_WriteProcessMemory_cf78 {
  strings:
    $key_cf78 = { 98 0a [2] aa 28 [2] ac 1d [2] 82 1d [2] bd 01 }

  condition:
    any of them
}