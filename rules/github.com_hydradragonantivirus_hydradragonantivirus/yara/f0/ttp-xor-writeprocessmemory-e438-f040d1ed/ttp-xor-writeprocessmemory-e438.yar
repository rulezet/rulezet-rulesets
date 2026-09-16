rule TTP_XOR_WriteProcessMemory_e438 {
  strings:
    $key_e438 = { b3 4a [2] 81 68 [2] 87 5d [2] a9 5d [2] 96 41 }

  condition:
    any of them
}