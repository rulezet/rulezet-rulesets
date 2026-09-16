rule TTP_XOR_WriteProcessMemory_52ca {
  strings:
    $key_52ca = { 05 b8 [2] 37 9a [2] 31 af [2] 1f af [2] 20 b3 }

  condition:
    any of them
}