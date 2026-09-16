rule TTP_XOR_WriteProcessMemory_7dac {
  strings:
    $key_7dac = { 2a de [2] 18 fc [2] 1e c9 [2] 30 c9 [2] 0f d5 }

  condition:
    any of them
}