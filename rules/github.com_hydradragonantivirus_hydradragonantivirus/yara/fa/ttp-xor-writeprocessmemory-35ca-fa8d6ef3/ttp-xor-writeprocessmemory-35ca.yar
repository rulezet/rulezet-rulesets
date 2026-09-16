rule TTP_XOR_WriteProcessMemory_35ca {
  strings:
    $key_35ca = { 62 b8 [2] 50 9a [2] 56 af [2] 78 af [2] 47 b3 }

  condition:
    any of them
}