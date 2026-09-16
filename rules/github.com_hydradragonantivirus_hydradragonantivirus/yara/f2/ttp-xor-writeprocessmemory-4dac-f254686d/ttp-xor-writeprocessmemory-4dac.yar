rule TTP_XOR_WriteProcessMemory_4dac {
  strings:
    $key_4dac = { 1a de [2] 28 fc [2] 2e c9 [2] 00 c9 [2] 3f d5 }

  condition:
    any of them
}