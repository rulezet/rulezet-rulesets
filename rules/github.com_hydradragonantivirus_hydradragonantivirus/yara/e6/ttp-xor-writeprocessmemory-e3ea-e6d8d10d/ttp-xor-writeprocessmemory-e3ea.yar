rule TTP_XOR_WriteProcessMemory_e3ea {
  strings:
    $key_e3ea = { b4 98 [2] 86 ba [2] 80 8f [2] ae 8f [2] 91 93 }

  condition:
    any of them
}