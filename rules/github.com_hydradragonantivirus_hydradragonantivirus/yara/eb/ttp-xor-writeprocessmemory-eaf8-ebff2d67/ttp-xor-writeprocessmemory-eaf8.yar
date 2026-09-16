rule TTP_XOR_WriteProcessMemory_eaf8 {
  strings:
    $key_eaf8 = { bd 8a [2] 8f a8 [2] 89 9d [2] a7 9d [2] 98 81 }

  condition:
    any of them
}