rule TTP_XOR_WriteProcessMemory_2fc8 {
  strings:
    $key_2fc8 = { 78 ba [2] 4a 98 [2] 4c ad [2] 62 ad [2] 5d b1 }

  condition:
    any of them
}