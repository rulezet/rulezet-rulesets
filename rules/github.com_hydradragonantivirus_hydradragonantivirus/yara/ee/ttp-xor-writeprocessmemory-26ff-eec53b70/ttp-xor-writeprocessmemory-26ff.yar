rule TTP_XOR_WriteProcessMemory_26ff {
  strings:
    $key_26ff = { 71 8d [2] 43 af [2] 45 9a [2] 6b 9a [2] 54 86 }

  condition:
    any of them
}