rule TTP_XOR_WriteProcessMemory_06f8 {
  strings:
    $key_06f8 = { 51 8a [2] 63 a8 [2] 65 9d [2] 4b 9d [2] 74 81 }

  condition:
    any of them
}