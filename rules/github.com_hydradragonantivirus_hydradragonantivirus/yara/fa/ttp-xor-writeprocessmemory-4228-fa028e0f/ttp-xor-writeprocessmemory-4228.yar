rule TTP_XOR_WriteProcessMemory_4228 {
  strings:
    $key_4228 = { 15 5a [2] 27 78 [2] 21 4d [2] 0f 4d [2] 30 51 }

  condition:
    any of them
}