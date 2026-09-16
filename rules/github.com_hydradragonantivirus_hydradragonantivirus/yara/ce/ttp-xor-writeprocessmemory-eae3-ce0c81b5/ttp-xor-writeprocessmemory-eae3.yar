rule TTP_XOR_WriteProcessMemory_eae3 {
  strings:
    $key_eae3 = { bd 91 [2] 8f b3 [2] 89 86 [2] a7 86 [2] 98 9a }

  condition:
    any of them
}