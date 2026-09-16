rule TTP_XOR_WriteProcessMemory_ea2a {
  strings:
    $key_ea2a = { bd 58 [2] 8f 7a [2] 89 4f [2] a7 4f [2] 98 53 }

  condition:
    any of them
}