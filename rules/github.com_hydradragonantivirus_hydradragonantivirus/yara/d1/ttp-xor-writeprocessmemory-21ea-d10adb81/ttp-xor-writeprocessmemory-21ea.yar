rule TTP_XOR_WriteProcessMemory_21ea {
  strings:
    $key_21ea = { 76 98 [2] 44 ba [2] 42 8f [2] 6c 8f [2] 53 93 }

  condition:
    any of them
}