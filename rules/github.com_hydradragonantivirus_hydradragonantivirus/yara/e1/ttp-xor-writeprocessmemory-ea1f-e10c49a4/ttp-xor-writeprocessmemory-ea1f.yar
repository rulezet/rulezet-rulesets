rule TTP_XOR_WriteProcessMemory_ea1f {
  strings:
    $key_ea1f = { bd 6d [2] 8f 4f [2] 89 7a [2] a7 7a [2] 98 66 }

  condition:
    any of them
}