rule TTP_XOR_WriteProcessMemory_e21b {
  strings:
    $key_e21b = { b5 69 [2] 87 4b [2] 81 7e [2] af 7e [2] 90 62 }

  condition:
    any of them
}