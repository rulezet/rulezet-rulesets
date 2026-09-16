rule TTP_XOR_WriteProcessMemory_b004 {
  strings:
    $key_b004 = { e7 76 [2] d5 54 [2] d3 61 [2] fd 61 [2] c2 7d }

  condition:
    any of them
}