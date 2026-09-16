rule TTP_XOR_WriteProcessMemory_80d3 {
  strings:
    $key_80d3 = { d7 a1 [2] e5 83 [2] e3 b6 [2] cd b6 [2] f2 aa }

  condition:
    any of them
}