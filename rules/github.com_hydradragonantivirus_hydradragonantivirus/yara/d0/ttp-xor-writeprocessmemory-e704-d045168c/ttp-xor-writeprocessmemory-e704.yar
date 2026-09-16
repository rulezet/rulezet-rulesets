rule TTP_XOR_WriteProcessMemory_e704 {
  strings:
    $key_e704 = { b0 76 [2] 82 54 [2] 84 61 [2] aa 61 [2] 95 7d }

  condition:
    any of them
}