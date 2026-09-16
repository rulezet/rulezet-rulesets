rule TTP_XOR_WriteProcessMemory_ea0a {
  strings:
    $key_ea0a = { bd 78 [2] 8f 5a [2] 89 6f [2] a7 6f [2] 98 73 }

  condition:
    any of them
}