rule TTP_XOR_WriteProcessMemory_1ce8 {
  strings:
    $key_1ce8 = { 4b 9a [2] 79 b8 [2] 7f 8d [2] 51 8d [2] 6e 91 }

  condition:
    any of them
}