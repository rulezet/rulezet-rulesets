rule TTP_XOR_WriteProcessMemory_23e8 {
  strings:
    $key_23e8 = { 74 9a [2] 46 b8 [2] 40 8d [2] 6e 8d [2] 51 91 }

  condition:
    any of them
}