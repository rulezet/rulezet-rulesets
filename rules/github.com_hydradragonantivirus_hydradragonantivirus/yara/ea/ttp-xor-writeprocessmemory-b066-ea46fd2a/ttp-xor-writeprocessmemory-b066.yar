rule TTP_XOR_WriteProcessMemory_b066 {
  strings:
    $key_b066 = { e7 14 [2] d5 36 [2] d3 03 [2] fd 03 [2] c2 1f }

  condition:
    any of them
}