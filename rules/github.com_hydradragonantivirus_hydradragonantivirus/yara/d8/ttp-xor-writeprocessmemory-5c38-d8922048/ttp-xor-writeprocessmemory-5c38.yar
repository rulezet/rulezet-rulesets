rule TTP_XOR_WriteProcessMemory_5c38 {
  strings:
    $key_5c38 = { 0b 4a [2] 39 68 [2] 3f 5d [2] 11 5d [2] 2e 41 }

  condition:
    any of them
}