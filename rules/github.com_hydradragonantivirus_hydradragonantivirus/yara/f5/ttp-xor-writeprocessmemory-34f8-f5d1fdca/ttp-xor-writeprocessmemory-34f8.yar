rule TTP_XOR_WriteProcessMemory_34f8 {
  strings:
    $key_34f8 = { 63 8a [2] 51 a8 [2] 57 9d [2] 79 9d [2] 46 81 }

  condition:
    any of them
}