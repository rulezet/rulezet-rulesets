rule TTP_XOR_WriteProcessMemory_52e8 {
  strings:
    $key_52e8 = { 05 9a [2] 37 b8 [2] 31 8d [2] 1f 8d [2] 20 91 }

  condition:
    any of them
}