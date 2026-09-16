rule TTP_XOR_WriteProcessMemory_a997 {
  strings:
    $key_a997 = { fe e5 [2] cc c7 [2] ca f2 [2] e4 f2 [2] db ee }

  condition:
    any of them
}