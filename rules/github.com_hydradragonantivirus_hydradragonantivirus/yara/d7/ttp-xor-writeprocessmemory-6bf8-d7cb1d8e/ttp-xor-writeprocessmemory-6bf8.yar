rule TTP_XOR_WriteProcessMemory_6bf8 {
  strings:
    $key_6bf8 = { 3c 8a [2] 0e a8 [2] 08 9d [2] 26 9d [2] 19 81 }

  condition:
    any of them
}