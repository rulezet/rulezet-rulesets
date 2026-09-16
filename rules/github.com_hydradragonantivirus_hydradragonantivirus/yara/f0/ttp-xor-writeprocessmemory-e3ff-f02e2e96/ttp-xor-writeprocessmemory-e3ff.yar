rule TTP_XOR_WriteProcessMemory_e3ff {
  strings:
    $key_e3ff = { b4 8d [2] 86 af [2] 80 9a [2] ae 9a [2] 91 86 }

  condition:
    any of them
}