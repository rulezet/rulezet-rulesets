rule TTP_XOR_WriteProcessMemory_3678 {
  strings:
    $key_3678 = { 61 0a [2] 53 28 [2] 55 1d [2] 7b 1d [2] 44 01 }

  condition:
    any of them
}