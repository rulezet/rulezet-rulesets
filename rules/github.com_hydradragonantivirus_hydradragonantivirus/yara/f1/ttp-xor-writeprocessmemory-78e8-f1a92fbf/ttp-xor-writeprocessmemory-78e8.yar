rule TTP_XOR_WriteProcessMemory_78e8 {
  strings:
    $key_78e8 = { 2f 9a [2] 1d b8 [2] 1b 8d [2] 35 8d [2] 0a 91 }

  condition:
    any of them
}