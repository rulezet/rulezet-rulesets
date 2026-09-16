rule TTP_XOR_WriteProcessMemory_26ba {
  strings:
    $key_26ba = { 71 c8 [2] 43 ea [2] 45 df [2] 6b df [2] 54 c3 }

  condition:
    any of them
}