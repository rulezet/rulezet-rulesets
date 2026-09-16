rule TTP_XOR_WriteProcessMemory_f501 {
  strings:
    $key_f501 = { a2 73 [2] 90 51 [2] 96 64 [2] b8 64 [2] 87 78 }

  condition:
    any of them
}