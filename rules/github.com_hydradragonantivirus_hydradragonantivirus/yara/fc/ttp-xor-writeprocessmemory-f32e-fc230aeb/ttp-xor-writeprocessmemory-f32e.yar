rule TTP_XOR_WriteProcessMemory_f32e {
  strings:
    $key_f32e = { a4 5c [2] 96 7e [2] 90 4b [2] be 4b [2] 81 57 }

  condition:
    any of them
}