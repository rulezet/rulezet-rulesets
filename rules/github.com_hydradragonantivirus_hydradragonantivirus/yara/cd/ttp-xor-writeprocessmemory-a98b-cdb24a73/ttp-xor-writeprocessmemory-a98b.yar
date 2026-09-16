rule TTP_XOR_WriteProcessMemory_a98b {
  strings:
    $key_a98b = { fe f9 [2] cc db [2] ca ee [2] e4 ee [2] db f2 }

  condition:
    any of them
}