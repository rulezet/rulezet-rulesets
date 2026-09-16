rule TTP_XOR_WriteProcessMemory_4278 {
  strings:
    $key_4278 = { 15 0a [2] 27 28 [2] 21 1d [2] 0f 1d [2] 30 01 }

  condition:
    any of them
}