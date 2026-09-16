rule TTP_XOR_WriteProcessMemory_20ca {
  strings:
    $key_20ca = { 77 b8 [2] 45 9a [2] 43 af [2] 6d af [2] 52 b3 }

  condition:
    any of them
}