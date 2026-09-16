rule TTP_XOR_WriteProcessMemory_eced {
  strings:
    $key_eced = { bb 9f [2] 89 bd [2] 8f 88 [2] a1 88 [2] 9e 94 }

  condition:
    any of them
}