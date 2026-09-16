rule TTP_XOR_WriteProcessMemory_e1ff {
  strings:
    $key_e1ff = { b6 8d [2] 84 af [2] 82 9a [2] ac 9a [2] 93 86 }

  condition:
    any of them
}