rule TTP_XOR_WriteProcessMemory_ae8f {
  strings:
    $key_ae8f = { f9 fd [2] cb df [2] cd ea [2] e3 ea [2] dc f6 }

  condition:
    any of them
}