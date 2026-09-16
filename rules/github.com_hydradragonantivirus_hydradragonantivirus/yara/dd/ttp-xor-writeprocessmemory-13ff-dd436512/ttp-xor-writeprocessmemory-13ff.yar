rule TTP_XOR_WriteProcessMemory_13ff {
  strings:
    $key_13ff = { 44 8d [2] 76 af [2] 70 9a [2] 5e 9a [2] 61 86 }

  condition:
    any of them
}