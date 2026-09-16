rule TTP_XOR_WriteProcessMemory_0538 {
  strings:
    $key_0538 = { 52 4a [2] 60 68 [2] 66 5d [2] 48 5d [2] 77 41 }

  condition:
    any of them
}