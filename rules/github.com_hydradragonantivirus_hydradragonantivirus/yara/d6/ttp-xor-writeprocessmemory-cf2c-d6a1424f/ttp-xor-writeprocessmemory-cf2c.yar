rule TTP_XOR_WriteProcessMemory_cf2c {
  strings:
    $key_cf2c = { 98 5e [2] aa 7c [2] ac 49 [2] 82 49 [2] bd 55 }

  condition:
    any of them
}