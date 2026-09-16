rule TTP_XOR_WriteProcessMemory_f338 {
  strings:
    $key_f338 = { a4 4a [2] 96 68 [2] 90 5d [2] be 5d [2] 81 41 }

  condition:
    any of them
}