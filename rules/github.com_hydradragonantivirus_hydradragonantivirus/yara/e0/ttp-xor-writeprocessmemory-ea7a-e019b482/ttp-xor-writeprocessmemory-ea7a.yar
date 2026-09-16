rule TTP_XOR_WriteProcessMemory_ea7a {
  strings:
    $key_ea7a = { bd 08 [2] 8f 2a [2] 89 1f [2] a7 1f [2] 98 03 }

  condition:
    any of them
}