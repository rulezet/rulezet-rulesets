rule TTP_XOR_WriteProcessMemory_e2ea {
  strings:
    $key_e2ea = { b5 98 [2] 87 ba [2] 81 8f [2] af 8f [2] 90 93 }

  condition:
    any of them
}