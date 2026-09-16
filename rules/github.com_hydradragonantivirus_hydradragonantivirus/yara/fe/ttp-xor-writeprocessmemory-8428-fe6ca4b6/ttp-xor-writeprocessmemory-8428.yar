rule TTP_XOR_WriteProcessMemory_8428 {
  strings:
    $key_8428 = { d3 5a [2] e1 78 [2] e7 4d [2] c9 4d [2] f6 51 }

  condition:
    any of them
}