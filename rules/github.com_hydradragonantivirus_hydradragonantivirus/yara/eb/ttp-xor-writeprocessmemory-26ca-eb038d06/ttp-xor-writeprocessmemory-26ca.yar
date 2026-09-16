rule TTP_XOR_WriteProcessMemory_26ca {
  strings:
    $key_26ca = { 71 b8 [2] 43 9a [2] 45 af [2] 6b af [2] 54 b3 }

  condition:
    any of them
}