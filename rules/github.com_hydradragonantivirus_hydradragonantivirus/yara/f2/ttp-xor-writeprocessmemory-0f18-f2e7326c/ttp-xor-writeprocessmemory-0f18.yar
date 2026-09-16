rule TTP_XOR_WriteProcessMemory_0f18 {
  strings:
    $key_0f18 = { 58 6a [2] 6a 48 [2] 6c 7d [2] 42 7d [2] 7d 61 }

  condition:
    any of them
}