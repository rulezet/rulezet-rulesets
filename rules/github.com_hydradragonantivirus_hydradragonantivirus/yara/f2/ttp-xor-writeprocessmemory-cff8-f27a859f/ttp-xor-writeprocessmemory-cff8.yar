rule TTP_XOR_WriteProcessMemory_cff8 {
  strings:
    $key_cff8 = { 98 8a [2] aa a8 [2] ac 9d [2] 82 9d [2] bd 81 }

  condition:
    any of them
}