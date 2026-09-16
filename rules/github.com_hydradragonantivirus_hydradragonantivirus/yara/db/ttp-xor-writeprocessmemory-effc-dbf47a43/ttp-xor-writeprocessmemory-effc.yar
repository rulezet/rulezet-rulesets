rule TTP_XOR_WriteProcessMemory_effc {
  strings:
    $key_effc = { b8 8e [2] 8a ac [2] 8c 99 [2] a2 99 [2] 9d 85 }

  condition:
    any of them
}