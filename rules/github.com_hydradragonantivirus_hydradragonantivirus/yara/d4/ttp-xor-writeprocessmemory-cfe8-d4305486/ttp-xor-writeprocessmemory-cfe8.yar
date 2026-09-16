rule TTP_XOR_WriteProcessMemory_cfe8 {
  strings:
    $key_cfe8 = { 98 9a [2] aa b8 [2] ac 8d [2] 82 8d [2] bd 91 }

  condition:
    any of them
}