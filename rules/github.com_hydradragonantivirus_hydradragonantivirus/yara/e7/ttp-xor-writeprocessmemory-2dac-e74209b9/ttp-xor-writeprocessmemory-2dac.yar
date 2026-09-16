rule TTP_XOR_WriteProcessMemory_2dac {
  strings:
    $key_2dac = { 7a de [2] 48 fc [2] 4e c9 [2] 60 c9 [2] 5f d5 }

  condition:
    any of them
}