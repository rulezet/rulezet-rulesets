rule TTP_XOR_WriteProcessMemory_e6ea {
  strings:
    $key_e6ea = { b1 98 [2] 83 ba [2] 85 8f [2] ab 8f [2] 94 93 }

  condition:
    any of them
}