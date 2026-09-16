rule TTP_XOR_WriteProcessMemory_f5e8 {
  strings:
    $key_f5e8 = { a2 9a [2] 90 b8 [2] 96 8d [2] b8 8d [2] 87 91 }

  condition:
    any of them
}