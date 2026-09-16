rule TTP_XOR_WriteProcessMemory_347d {
  strings:
    $key_347d = { 63 0f [2] 51 2d [2] 57 18 [2] 79 18 [2] 46 04 }

  condition:
    any of them
}