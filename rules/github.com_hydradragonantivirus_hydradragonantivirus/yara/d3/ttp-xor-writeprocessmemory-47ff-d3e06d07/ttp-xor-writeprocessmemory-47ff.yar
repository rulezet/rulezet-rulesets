rule TTP_XOR_WriteProcessMemory_47ff {
  strings:
    $key_47ff = { 10 8d [2] 22 af [2] 24 9a [2] 0a 9a [2] 35 86 }

  condition:
    any of them
}