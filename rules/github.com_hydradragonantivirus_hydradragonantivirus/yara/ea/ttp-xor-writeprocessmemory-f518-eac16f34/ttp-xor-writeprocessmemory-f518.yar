rule TTP_XOR_WriteProcessMemory_f518 {
  strings:
    $key_f518 = { a2 6a [2] 90 48 [2] 96 7d [2] b8 7d [2] 87 61 }

  condition:
    any of them
}