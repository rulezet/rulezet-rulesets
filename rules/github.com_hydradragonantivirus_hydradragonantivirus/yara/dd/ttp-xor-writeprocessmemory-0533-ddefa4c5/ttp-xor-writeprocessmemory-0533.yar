rule TTP_XOR_WriteProcessMemory_0533 {
  strings:
    $key_0533 = { 52 41 [2] 60 63 [2] 66 56 [2] 48 56 [2] 77 4a }

  condition:
    any of them
}