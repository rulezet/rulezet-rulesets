rule TTP_XOR_WriteProcessMemory_e101 {
  strings:
    $key_e101 = { b6 73 [2] 84 51 [2] 82 64 [2] ac 64 [2] 93 78 }

  condition:
    any of them
}