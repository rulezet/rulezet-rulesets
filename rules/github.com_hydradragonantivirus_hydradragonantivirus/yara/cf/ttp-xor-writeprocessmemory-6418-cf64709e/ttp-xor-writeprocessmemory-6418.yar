rule TTP_XOR_WriteProcessMemory_6418 {
  strings:
    $key_6418 = { 33 6a [2] 01 48 [2] 07 7d [2] 29 7d [2] 16 61 }

  condition:
    any of them
}