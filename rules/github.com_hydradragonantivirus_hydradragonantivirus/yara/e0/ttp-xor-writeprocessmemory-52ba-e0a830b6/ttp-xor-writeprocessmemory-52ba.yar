rule TTP_XOR_WriteProcessMemory_52ba {
  strings:
    $key_52ba = { 05 c8 [2] 37 ea [2] 31 df [2] 1f df [2] 20 c3 }

  condition:
    any of them
}